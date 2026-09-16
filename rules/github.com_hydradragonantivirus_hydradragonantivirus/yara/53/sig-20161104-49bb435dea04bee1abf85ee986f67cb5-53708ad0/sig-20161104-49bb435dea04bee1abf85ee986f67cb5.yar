rule sig_20161104_49bb435dea04bee1abf85ee986f67cb5 {
  meta:
    description = "datamaliciousorder - file 20161104_49bb435dea04bee1abf85ee986f67cb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba4356c65a29f1300632fb9061af965cba2939033510824bdddf54b45c89aa6f"

  strings:
    $s1  = "var atdeta = \"return typeof WScript.Std\";" fullword ascii
    $s2  = "var sopaxt = new Function(atdeta + \"In.AtEndOfStream == 'unknown'\")();" fullword ascii
    $s3  = "function fzonikgyje() {" fullword ascii
    $s4  = "var tody = \"s\";" fullword ascii
    $s5  = "var yzizwexo = null;" fullword ascii
    $s6  = "var ulwanelnu = null;" fullword ascii
    $s7  = "return \"haxzer\";" fullword ascii
    $s8  = "function pluhopyqd() {" fullword ascii
    $s9  = "var inass = [onjikva, tody, knapigbo, unokwecz, icsabel, tojfo, wyrcerwi, qmucsexa, pyzvycko, betkiby, ptiklyd, imnoxq, ismopna," ascii
    $s10 = "return dyrdicqebv;" fullword ascii
    $s11 = "return aputcecj;" fullword ascii
    $s12 = "return \"4481\";" fullword ascii
    $s13 = "function dpanwece() {" fullword ascii
    $s14 = "var yfgycwopmi = undefined;" fullword ascii
    $s15 = "function jefahm() {" fullword ascii
    $s16 = "function grupakilw() {" fullword ascii
    $s17 = "function xmuzjaze() {" fullword ascii
    $s18 = "var cysahusfa = null;" fullword ascii
    $s19 = "function xgunwequdq() {" fullword ascii
    $s20 = "function ynhovlityk() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}