rule sig_20160311_7c743ab6dbb0747d050be24dea8bd090 {
  meta:
    description = "datamaliciousorder - file 20160311_7c743ab6dbb0747d050be24dea8bd090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b5631b904cbeb150c7d4892d61849596331333e9e88e038311ca0dca6d0d81"

  strings:
    $s1  = "_evalUrl = 6, truncate = \"WSc\", arg = \"e\", stateVal = 33, relatedTarget = \"%TEMP%\";" fullword ascii
    $s2  = "pipe[\"sav\" + rbracket + \"ile\"](deepDataAndEvents, ((212, options) & (1 * options)));" fullword ascii
    $s3  = "dataFilter, (162 / whitespace), 23) & (((proxy | 7) & (createComment, 28, crossDomain, 15)) + ((unique / 16) / sortStable * 7)))" ascii
    $s4  = "pipe = rnamespace[\"WScrip\".nType() + finalDataType][\"Cre\" + newSelector + \"bje\" + div1](\"ADODB.\".nType() + _default);" fullword ascii
    $s5  = "handle[dataType + \"en\".nType()](simple + \"ET\", offset + \"p://nr\" + focusin + \"sd/23r\".nType() + now + \"44y5\", !((((((1" ascii
    $s6  = "pipe[\"op\" + arg + \"n\"]();" fullword ascii
    $s7  = "rmargin[box + \"n\".nType()](deepDataAndEvents.nType(((slideUp & 85), (risSimple / 26), (domManip & 91))), ((test, 33) - (stateV" ascii
    $s8  = "handle[dataType + \"en\".nType()](simple + \"ET\", offset + \"p://nr\" + focusin + \"sd/23r\".nType() + now + \"44y5\", !((((((1" ascii
    $s9  = "w[prototype + \"p\".nType() + arg] = ((1 * dataFilter) * (34 - stateVal));" fullword ascii
    $s10 = "rmargin[box + \"n\".nType()](deepDataAndEvents.nType(((slideUp & 85), (risSimple / 26), (domManip & 91))), ((test, 33) - (stateV" ascii
    $s11 = "handle[readyState + \"e\" + speeds]();" fullword ascii
    $s12 = "rnamespace = (((66 - tokenCache) + (4 | always)), ((128 / deep) + (61 - visibility)), eval(\"th\" + rdisplayswap));" fullword ascii
    $s13 = "pdataOld = pipe;" fullword ascii
    $s14 = "lter) / (6 | MAX_NEGATIVE))) | ((2 | rparentsprev) * (20 - funescape) * 2 * ((param / 43) + (func - 36)))) & (((uniqueID - 17), " ascii
    $s15 = "pdataOld[tick + \"lose\".nType()]();" fullword ascii
    $s16 = "isSimulated = rnamespace[\"WScr\".nType() + padding];" fullword ascii
    $s17 = "handle = rnamespace[parentOffset + \"ipt\"][m + \"ateO\".nType() + booleans](\"MSXML\" + showHide + \"TTP\");" fullword ascii
    $s18 = "root();" fullword ascii
    $s19 = "xml = \"onme\", test = 38, tick = \"c\", padding = \"ipt\", proxy = 10, crossDomain = 117;" fullword ascii
    $s20 = "w = pipe;" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}