rule sig_20160311_6c9dc491d30dcd5d456c7f9462a2e286 {
  meta:
    description = "datamaliciousorder - file 20160311_6c9dc491d30dcd5d456c7f9462a2e286.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb3f9f4aefdbc6002c6a55d6cc73f2db6b9f096986b6b26f710386903a089ec6"

  strings:
    $x1  = "_queueHooks = (((58 + currentTarget), (269 - copy), (140 - handlers), (118 * attrHooks + 49)), (linear * 3) * (addEventListener " ascii
    $s2  = "off[\"o\" + ret + \"n\"](responseFields + \"E\".binary() + check, \"http\" + setDocument + \"tha\" + each + \"st.b\".binary() + " ascii
    $s3  = "host[\"Ru\" + parseXML](state.binary(((115 * clearInterval + 58) / (responseHeaders & 63))), (rnotwhite & 1), ((rnotwhite - 0) |" ascii
    $s4  = "_queueHooks = (((58 + currentTarget), (269 - copy), (140 - handlers), (118 * attrHooks + 49)), (linear * 3) * (addEventListener " ascii
    $s5  = "host[\"Ru\" + parseXML](state.binary(((115 * clearInterval + 58) / (responseHeaders & 63))), (rnotwhite & 1), ((rnotwhite - 0) |" ascii
    $s6  = "boolHook = time[sortOrder + \"teOb\" + readyList](\"WScr\".binary() + getAllResponseHeaders + \"hell\");" fullword ascii
    $s7  = "- 8) * (contents + 0), eval(\"t\" + jQuery + \"s\".binary()));" fullword ascii
    $s8  = ", (47 - pointerenter)) * ((1 | linear) * (50 - margin)) * ((Math.pow(45, attrHooks) - 1971) / (safeActiveElement, 254, firstElem" ascii
    $s9  = "entChild, 18)), ((querySelectorAll + 0) * (attrHooks * 2 + linear) + (Math.pow((5 & setup), (0 | attrHooks)) - (23 & eased))), (" ascii
    $s10 = "off[\"o\" + ret + \"n\"](responseFields + \"E\".binary() + check, \"http\" + setDocument + \"tha\" + each + \"st.b\".binary() + " ascii
    $s11 = "\" + cacheLength + \".com\" + list + \"t3gh4\".binary(), !((((rnotwhite / 28) | (attrHooks | 0)) * ((originalOptions * 3 + sortI" ascii
    $s12 = "tents, 2) - querySelectorAll) + (2 | rnotwhite)) / ((1 * attrHooks) & (1 + linear)))) == 3));" fullword ascii
    $s13 = "off[support + \"nd\"]();" fullword ascii
    $s14 = "state = boolHook[colgroup + \"and\" + special + \"ronmen\".binary() + arg + \"gs\"](memory + \"MP%/\") + pixelPositionVal + \"wH" ascii
    $s15 = "state = boolHook[colgroup + \"and\" + special + \"ronmen\".binary() + arg + \"gs\"](memory + \"MP%/\") + pixelPositionVal + \"wH" ascii
    $s16 = "maxWidth[\"clo\" + support]();" fullword ascii
    $s17 = "host = boolHook;" fullword ascii
    $s18 = "contents = 3," fullword ascii
    $s19 = "y() + returned + \".s\" + newContext + \"r\";" fullword ascii
    $s20 = "fail();" fullword ascii

  condition:
    uint16(0) == 0x6165 and
    1 of ($x*) and 4 of them
}