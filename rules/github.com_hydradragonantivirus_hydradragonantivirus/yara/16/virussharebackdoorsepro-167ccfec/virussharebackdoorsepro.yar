rule VirusShareBackDoorSepro {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorSepro.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fa67514488fcf39773c722b5d49c051e115d57155122276e99453541682e593"

  strings:
    $x1  = "PRIVMSG %s :couldn't spawn ftp.exe" fullword ascii
    $x2  = "PRIVMSG %s :successfully spawned ftp.exe" fullword ascii
    $s3  = "PRIVMSG %s :ctcp <nick> PING 848348, help, getnick <nick>, getnonick, rnick <nick>!!, sacker time low_port high_port addy, jacke" ascii
    $s4  = "PRIVMSG %s :ctcp <nick> PING 848348, help, getnick <nick>, getnonick, rnick <nick>!!, sacker time low_port high_port addy, jacke" ascii
    $s5  = "r time ip ip ip etc, stopsack, stopjack, spawn filename, ftpget EVERYTHING, randnick, clone, clonedie" fullword ascii
    $s6  = "PRIVMSG %s :couldn't spawn file" fullword ascii
    $s7  = "USER %s %s %s :%s" fullword ascii
    $s8  = "JOIN #%s,#%s" fullword ascii
    $s9  = "Service Profiler" fullword ascii
    $s10 = "PRIVMSG %s :ok.. running" fullword ascii
    $s11 = "PRIVMSG %s :ready and willing..." fullword ascii
    $s12 = "PONG %s" fullword ascii
    $s13 = "JOIN #%s" fullword ascii
    $s14 = "NICK %c" fullword ascii
    $s15 = "NICK %s" fullword ascii
    $s16 = "SERVER%d" fullword ascii
    $s17 = "SACKER" fullword ascii
    $s18 = "JACKER" fullword ascii
    $s19 = "PRIVMSG %s :no more..." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}