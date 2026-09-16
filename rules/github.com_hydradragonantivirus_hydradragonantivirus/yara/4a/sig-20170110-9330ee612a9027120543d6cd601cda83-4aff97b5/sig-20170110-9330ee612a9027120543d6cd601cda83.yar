rule sig_20170110_9330ee612a9027120543d6cd601cda83 {
  meta:
    description = "datamaliciousorder - file 20170110_9330ee612a9027120543d6cd601cda83.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2196fe2f79495368d26102d5d54a771316455fa4917c6edd12488059662cdb8b"

  strings:
    $x1  = "var jqutzo = \"cmd.exe /c \\\"po\" + \"we\" + \"rs\" + \"he\" + \"ll  $ojogo='^dimas.top';$hetfo='^-Scope  Pr';$pobbi='^,$path);" ascii
    $x2  = "var jqutzo = \"cmd.exe /c \\\"po\" + \"we\" + \"rs\" + \"he\" + \"ll  $ojogo='^dimas.top';$hetfo='^-Scope  Pr';$pobbi='^,$path);" ascii
    $s3  = "'^ocess; $p';$monsucm='^y Bypass ';$binkucb='^h';$ykpyffy='^Start-Pro';$ykjygr='^:temp+''\\b';$uzmez='^e'');(New-';$xzymo='^Set-" ascii
    $s4  = "var ubahgoliw = undefined;" fullword ascii
    $s5  = "var itpirnezmiv = undefined;" fullword ascii
    $s6  = "return pdewi;" fullword ascii
    $s7  = "function alfyplessap() {" fullword ascii
    $s8  = "var ytivy = true;" fullword ascii
    $s9  = "function ywugo() {" fullword ascii
    $s10 = "function emesysicq() {" fullword ascii
    $s11 = "function fqykrudlimg() {" fullword ascii
    $s12 = "var ydxezbonb = undefined;" fullword ascii
    $s13 = "switch (salhy()) {" fullword ascii
    $s14 = "switch (yrbyjivs) {" fullword ascii
    $s15 = "var ymabnetlo = undefined;" fullword ascii
    $s16 = "var xyskubsahs = null;" fullword ascii
    $s17 = "function apmij() {" fullword ascii
    $s18 = "var femudr = null;" fullword ascii
    $s19 = "switch (epjutgywxa()) {" fullword ascii
    $s20 = "var weslyh = undefined;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}