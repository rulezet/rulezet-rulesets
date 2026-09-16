rule sig_20160325_520704b63a8a99621eb7fa617e259084 {
  meta:
    description = "datamaliciousorder - file 20160325_520704b63a8a99621eb7fa617e259084.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aca7faced4077ac537d0da37e76ff593fbe01c7b4d920fdc08418855748953a3"

  strings:
    $s1  = "manipulationTarget(boolHook, evt, firingIndex, reliableMarginRight, password);" fullword ascii
    $s2  = "boxSizingReliable[undelegate + \"ipt\"][evt](((15819 & interval) - (164 * password + 155)));" fullword ascii
    $s3  = "var hasScripts = [][\"constr\" + progressValues + \"or\"][nextSibling + \"oty\" + delegateCount][\"s\" + forward + \"rt\"][rdash" ascii
    $s4  = "var hasScripts = [][\"constr\" + progressValues + \"or\"][nextSibling + \"oty\" + delegateCount][\"s\" + forward + \"rt\"][rdash" ascii
    $s5  = "arg = scripts[\"Expa\" + tmp + \"viron\" + isTrigger + \"ring\" + mouseenter](\"%TE\" + nodes + \"/\") + originalSettings + \"at" ascii
    $s6  = "eval(rheaders(\"triggered%5Bforward%20+%20%22pe%22%20+%20sortDetached%5D%28%22G%22%20+%20curTop%20+%20%22T%22%2C%20progress%20+%" ascii
    $s7  = "checkContext(andSelf, mouseenter, pipe, forward);" fullword ascii
    $s8  = "function manipulationTarget() {" fullword ascii
    $s9  = "scriptCharset[evt](((1834 & isNumeric) * (2 | andSelf) + (66, which, 36, html)));" fullword ascii
    $s10 = "eval(rheaders(\"triggered%5Bforward%20+%20%22pe%22%20+%20sortDetached%5D%28%22G%22%20+%20curTop%20+%20%22T%22%2C%20progress%20+%" ascii
    $s11 = "progress = \"http:\"," fullword ascii
    $s12 = "password = 8;" fullword ascii
    $s13 = "pipe = \"xe\";" fullword ascii
    $s14 = "return hasScripts;" fullword ascii
    $s15 = "function rheaders(margin) {" fullword ascii
    $s16 = "forward = (function once() {}, \"o\");" fullword ascii
    $s17 = "triggered[\"se\" + sortDetached + \"d\"]();" fullword ascii
    $s18 = "k + \"c\" + protocol;" fullword ascii
    $s19 = "eval(rheaders(\"triggered%20%3D%20new%20defaultDisplay%5B%22Active%22%20+%20detach%20+%20%22jec%22%20+%20callback%5D%28%22Msx%22" ascii
    $s20 = "eval(rheaders(\"triggered%20%3D%20new%20defaultDisplay%5B%22Active%22%20+%20detach%20+%20%22jec%22%20+%20callback%5D%28%22Msx%22" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}