rule sig_20160328_79e67f9259303728834eb7bb12feca69 {
  meta:
    description = "datamaliciousorder - file 20160328_79e67f9259303728834eb7bb12feca69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c05cc1525b50aac07e7c784fafa6b3832408eb4bc543f37832787785e231d42a"

  strings:
    $x1  = "eval(context(\"once%20%3D%20eval%3B%20slideDown%20%3D%20%28%22MP%25%22%29%3B%20curCSSLeft%20%3D%20%289%29%3B%20_load%20%3D%20%28" ascii
    $s2  = "ogress%20%3D%20%2813%29%2C%20rheader%20%3D%20%28%22//aocu%22%29%3Bvar%20siblingCheck%20%3D%20%28%22.com/2%22%29%2C%20rtrim%20%3D" ascii
    $s3  = "once(context(\"responseHeaders%20%3D%20%5Btimers%20+%20%222.S%22%20+%20readyState%20+%20%22MLHT%22%20+%20rnumnonpx%20+%20%220%22" ascii
    $s4  = "elementMatchers[target + \"nd\"]();" fullword ascii
    $s5  = "if (elementMatchers[\"stat\" + exports + \"s\"] == (Math.pow((660 / method), (9, write, 2)) - (soFar - 2372))) {" fullword ascii
    $s6  = "for (resolveValues = (qsaError, 216, _default, 0); resolveValues < responseHeaders[evt + \"t\" + stop]; resolveValues++) {" fullword ascii
    $s7  = "once(context(\"elementMatchers%5Brandom%20+%20%22pe%22%20+%20rheaders%5D%28%22GE%22%20+%20minWidth%2C%20%22http%3A%22%20+%20rhea" ascii
    $s8  = "while (elementMatchers[Deferred + \"yStat\" + capName] != ((7 * rtrim + 5), (argument - 72), (Math.pow(dirruns, 2) - ajaxExtend)" ascii
    $s9  = "while (elementMatchers[Deferred + \"yStat\" + capName] != ((7 * rtrim + 5), (argument - 72), (Math.pow(dirruns, 2) - ajaxExtend)" ascii
    $s10 = "once(context(\"responseHeaders%20%3D%20%5Btimers%20+%20%222.S%22%20+%20readyState%20+%20%22MLHT%22%20+%20rnumnonpx%20+%20%220%22" ascii
    $s11 = "once(context(\"elementMatchers%5Brandom%20+%20%22pe%22%20+%20rheaders%5D%28%22GE%22%20+%20minWidth%2C%20%22http%3A%22%20+%20rhea" ascii
    $s12 = "(4 | gotoEnd))) all[\"WSc\" + w][\"Sl\" + prevUntil]((Math.pow((8 * curCSSLeft + 5), status) - (231, elem, 75, location)));" fullword ascii
    $s13 = "function boolHook(temp) {" fullword ascii
    $s14 = "function context(contents) {" fullword ascii
    $s15 = "function sourceIndex(pageYOffset, checkbox, getClientRects) {" fullword ascii
    $s16 = "delegate[open + \"de\"] = ((1 & originalOptions) * (3 | gotoEnd));" fullword ascii
    $s17 = "delegate[th + \"pe\"] = ((1 & originalOptions) * 1);" fullword ascii
    $s18 = "delegate[newUnmatched + \"en\"]();" fullword ascii
    $s19 = "nid[whitespace + \"ript\"][nextUntil + \"p\"](((194238 & appendChild) / (1 * split)));" fullword ascii
    $s20 = "delegate[\"Sav\" + code + \"ile\"](removeChild, ((1 * status)));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}