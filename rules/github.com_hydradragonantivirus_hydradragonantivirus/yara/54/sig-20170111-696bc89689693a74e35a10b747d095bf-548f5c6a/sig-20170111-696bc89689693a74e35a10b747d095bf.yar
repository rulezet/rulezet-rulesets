rule sig_20170111_696bc89689693a74e35a10b747d095bf {
  meta:
    description = "datamaliciousorder - file 20170111_696bc89689693a74e35a10b747d095bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fc165331d38973d8d6ffec6fc2a462b81080ad41aca8f63d10f511a5c68080a"

  strings:
    $x1  = "var nqulpygto = \"cmd.exe /c \\\"po\" + \"we\" + \"rs\" + \"he\" + \"ll  $enark='^     System.Net';$pweli='^le(''http://';$ujgyv" ascii
    $x2  = "as.t';$qpoxuqg='^Set-Executi';$ggowe='^pass   -Scope';$ybzuvj='^     Process; $';$ejyfg='^temp+''\\acqe';$ovgodu='^,$path); St';" ascii
    $s3  = "isozo='^.Webclient)';$lodxa='^art-Process';$jbehvu='^ $path';$opgebhe='^onPolicy    By';$mosvocs='^path=($env:';$ewmony='^.Downl" ascii
    $s4  = "switch (unvums()) {" fullword ascii
    $s5  = "function ksore() {" fullword ascii
    $s6  = "if (asiztu == undefined) {" fullword ascii
    $s7  = "function amygi() {" fullword ascii
    $s8  = "var ermuvtafw = undefined;" fullword ascii
    $s9  = "function ekip() {" fullword ascii
    $s10 = "var ozomqyvq = false;" fullword ascii
    $s11 = "if (lhobhiwt == true) {" fullword ascii
    $s12 = "var uvgyf = null;" fullword ascii
    $s13 = "switch (lyssugxidr) {" fullword ascii
    $s14 = "function lihaqz() {" fullword ascii
    $s15 = "function uphot() {" fullword ascii
    $s16 = "var rcimegloha = null;" fullword ascii
    $s17 = "var enybxuhm = false;" fullword ascii
    $s18 = "var yjaktyhcyvj = null;" fullword ascii
    $s19 = "return rcimegloha;" fullword ascii
    $s20 = "var lyssugxidr = undefined;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}