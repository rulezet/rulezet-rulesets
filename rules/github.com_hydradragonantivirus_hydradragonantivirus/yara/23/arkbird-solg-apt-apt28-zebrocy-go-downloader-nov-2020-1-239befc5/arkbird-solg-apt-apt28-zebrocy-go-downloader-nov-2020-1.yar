import "pe"
rule ARKBIRD_SOLG_APT_APT28_Zebrocy_GO_Downloader_Nov_2020_1: FILE {
  meta:
    description = "Detect Zebrocy Go downloader (November 2020)"
    author      = "Arkbird_SOLG"
    id          = "114c0297-7168-5d20-b56b-89b0b47f18c7"
    date        = "2020-12-09"
    modified    = "2020-12-10"
    reference   = "https://www.intezer.com/blog/research/russian-apt-uses-covid-19-lures-to-deliver-zebrocy/"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-09/APT28/APT_APT28_Nov_2020_1.yar#L37-L65"
    license_url = "N/A"
    logic_hash  = "e7b2e7c250f3a98127399176adf9f93b758f0a5111e126dd0a75a3fb95a48da9"
    score       = 50
    quality     = 61
    tags        = "FILE"
    level       = "experimental"
    hash1       = "61c2e524dcc25a59d7f2fe7eff269865a3ed14d6b40e4fea33b3cd3f58c14f19"
    hash2       = "f36a0ee7f4ec23765bb28fbfa734e402042278864e246a54b8c4db6f58275662"

  strings:
    $c1  = "os.(*ProcessState).sys" fullword ascii
    $c2  = "os/exec.(*ExitError).Sys" fullword ascii
    $c3  = "os/exec.ExitError.Sys" fullword ascii
    $c4  = "os.(*ProcessState).Sys" fullword ascii
    $p1  = "syscall.CreatePipe" fullword ascii
    $p2  = "os.Pipe" fullword ascii
    $p3  = "net/http.(*http2pipe).closeDoneLocked"
    $p4  = "net/http.(*http2clientStream).getStartedWrite"
    $op1 = "u_g=%s %q%s*%d%s=%s&#34;&#39;&amp;"
    $op2 = "pc=%!(NOVERB)%!Weekday(%s|%s%s|%s(BADINDEX)"
    $op3 = "HTTP_PROXYHost: %s\r\nIP addressKeep-Alive"
    $op4 = "connection error: %sconnection timed out"
    $op5 = "-----BEGIN RSA TESTING KEY-----"
    $op6 = "-----END RSA TESTING KEY-----"

  condition:
    uint16(0) == 0x4d5a and filesize > 800KB and (pe.imphash() == "91802a615b3a5c4bcc05bc5f66a5b219") and 3 of ($c*) and 3 of ($p*) and 3 of ($op*)
}