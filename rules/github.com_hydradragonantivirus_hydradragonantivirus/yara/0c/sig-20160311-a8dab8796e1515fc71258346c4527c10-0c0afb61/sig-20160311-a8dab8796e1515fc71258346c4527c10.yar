rule sig_20160311_a8dab8796e1515fc71258346c4527c10 {
  meta:
    description = "datamaliciousorder - file 20160311_a8dab8796e1515fc71258346c4527c10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "812d35fbe326e3fd17cb5189ae3246284a4bdfc5c447068e1a0eedfcc236f318"

  strings:
    $s1  = "shift[\"o\" + addBack + \"n\"](curValue + \"ET\".rnoInnerhtml(), abort + \"://\" + finalDataType + \"dic\" + cssNormalTransform " ascii
    $s2  = "postFinder[\"saveTo\".rnoInnerhtml() + preMap](postDispatch, ((47 - onreadystatechange) | (6 / identifier)));" fullword ascii
    $s3  = "postDispatch = nid[\"Expand\" + byElement + \"iro\".rnoInnerhtml() + replaceWith + \"Str\" + clazz](\"%TEMP\" + hasClass) + \"cu" ascii
    $s4  = "shift[\"o\" + addBack + \"n\"](curValue + \"ET\".rnoInnerhtml(), abort + \"://\" + finalDataType + \"dic\" + cssNormalTransform " ascii
    $s5  = "rbuggyQSA[\"R\" + dispatch](postDispatch.rnoInnerhtml(((183 - rdisplayswap) - (68 | style))), (50 - done), (1 & (rlocalProtocol " ascii
    $s6  = "rbuggyQSA[\"R\" + dispatch](postDispatch.rnoInnerhtml(((183 - rdisplayswap) - (68 | style))), (50 - done), (1 & (rlocalProtocol " ascii
    $s7  = "4) * (safeActiveElement * 2 + identifier) * (4 - matcher) * (3 & matcher) * (0 | matcher), ((2313 * matcher + 954) / (emptyStyle" ascii
    $s8  = "specified = (((49 * matcher + 43) * (diff, 2) + (seekingTransport | 4)), ((elements | 166) / (seekingTransport * 4 + identifier)" ascii
    $s9  = "v = specified[\"WSc\".rnoInnerhtml() + script + \"t\"];" fullword ascii
    $s10 = "specified = (((49 * matcher + 43) * (diff, 2) + (seekingTransport | 4)), ((elements | 166) / (seekingTransport * 4 + identifier)" ascii
    $s11 = "postFinder = specified[\"WSc\".rnoInnerhtml() + ajaxConvert][\"Create\" + realStringObj + \"ct\"](list + \".St\".rnoInnerhtml() " ascii
    $s12 = "postFinder = specified[\"WSc\".rnoInnerhtml() + ajaxConvert][\"Create\" + realStringObj + \"ct\"](list + \".St\".rnoInnerhtml() " ascii
    $s13 = "noInnerhtml() + parseOnly + \"5g\", !((((((216, show) + (103 & values)) & ((69 * matcher + 6) - (handlers * 2))) & ((unmatched -" ascii
    $s14 = "shift = specified[lname + \"pt\".rnoInnerhtml()][activeElement + \"eOb\" + fail](\"MSXM\" + namespaces + \"XMLHTT\".rnoInnerhtml" ascii
    $s15 = "((rlocalProtocol / (286 / hasDuplicate)) | ((134 - random) - 2 * escapedWhitespace * 2)))) > seekingTransport));" fullword ascii
    $s16 = "nerhtml() + hash + \".s\" + setDocument + \"r\";" fullword ascii
    $s17 = "shift = specified[lname + \"pt\".rnoInnerhtml()][activeElement + \"eOb\" + fail](\"MSXM\" + namespaces + \"XMLHTT\".rnoInnerhtml" ascii
    $s18 = "htmlPrefilter = \"d\", abort = \"http\", random = 82, inspectPrefiltersOrTransports = 225, fail = \"ject\", matcher = 2;" fullword ascii
    $s19 = "script = \"rip\";" fullword ascii
    $s20 = "shift[iNoClone + \"n\" + htmlPrefilter]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}