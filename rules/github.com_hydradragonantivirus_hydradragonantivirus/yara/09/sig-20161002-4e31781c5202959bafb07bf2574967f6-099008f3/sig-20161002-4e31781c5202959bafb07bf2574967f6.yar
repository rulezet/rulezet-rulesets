rule sig_20161002_4e31781c5202959bafb07bf2574967f6 {
  meta:
    description = "datamaliciousorder - file 20161002_4e31781c5202959bafb07bf2574967f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4bc87ed65f8390ccf3ecd250a3b92a60b769a84828ba93aba04d4d86cf139a0"

  strings:
    $x1  = "ebadrohaq.run(\"cMd.EXe /c po^WerShELl^.eXe   -^ExECuTIO^nP^O^LIC^y  byP^AsS  -n^o^p^r^OfIle  ^-^WINdoW^stYLe    h^i^Dd^E^n    (" ascii
    $s2  = "-PR^OCess ^'%AppDaTA%.exe'\", false);" fullword ascii
    $s3  = "nyweji = omwolvid + utile;" fullword ascii
    $s4  = "function ecsyl() {" fullword ascii
    $s5  = "return ityqg;" fullword ascii
    $s6  = "var uxlijopy = undefined;" fullword ascii
    $s7  = "return mcunyqact;" fullword ascii
    $s8  = "function uxhigh() {" fullword ascii
    $s9  = "var utile = 446;" fullword ascii
    $s10 = "if (typeof document == \"undefined\") {" fullword ascii
    $s11 = "function orruhage() {" fullword ascii
    $s12 = "if (nohezyx() === null) {" fullword ascii
    $s13 = "function hyfy() {" fullword ascii
    $s14 = "var ityqg = true;" fullword ascii
    $s15 = "return \"e.do\";" fullword ascii
    $s16 = "function okotkoni() {" fullword ascii
    $s17 = "function zvotbej() {" fullword ascii
    $s18 = "var exyjycqiq = null;" fullword ascii
    $s19 = "function ipwymo() {" fullword ascii
    $s20 = "return \"/bo\";" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}