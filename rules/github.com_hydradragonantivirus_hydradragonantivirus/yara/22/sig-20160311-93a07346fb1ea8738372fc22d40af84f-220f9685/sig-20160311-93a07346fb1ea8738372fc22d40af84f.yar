rule sig_20160311_93a07346fb1ea8738372fc22d40af84f {
  meta:
    description = "datamaliciousorder - file 20160311_93a07346fb1ea8738372fc22d40af84f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb62d3265f3c17b4c87c35ea24138ab99e6ad8aa1efa38966807729be180e34e"

  strings:
    $s1  = "props[context + \"n\"](expanded.charset((89 | (attributes, 69, curCSS, 88))), (copy / (Math.pow(23, amd) - 501)), (copy / (360 /" ascii
    $s2  = "lname[rprotocol + \"eToF\".charset() + preFilters](expanded, (target + (1 * target)));" fullword ascii
    $s3  = "seed[\"o\".charset() + second + \"n\"](returnValue + \"ET\", iNoClone + \"//www.\".charset() + writable + \"tav.co\" + rmouseEve" ascii
    $s4  = "props[context + \"n\"](expanded.charset((89 | (attributes, 69, curCSS, 88))), (copy / (Math.pow(23, amd) - 501)), (copy / (360 /" ascii
    $s5  = "target = 1;" fullword ascii
    $s6  = "childNodes[\"ty\".charset() + errorCallback + \"e\"] = ((siblings / 44), (fragment - 69), newCache * 2, (conv2, 1));" fullword ascii
    $s7  = "pageX = ((124, raw * 2 * offsetHeight, (10 + computed)), (1 | copy), eval(\"th\" + constructor + \"s\".charset()));" fullword ascii
    $s8  = "globalEventContext = setMatched[val + \"Object\"](isWindow + \"pt.She\".charset() + show);" fullword ascii
    $s9  = "Map\" + prepend + \"c\".charset() + combinator;" fullword ascii
    $s10 = "seed = pageX[\"WSc\" + setTimeout][\"Crea\" + initial + \"ct\".charset()](image + \"ML2\" + anim + \"LHTT\" + hookFn);" fullword ascii
    $s11 = "lname = pageX[\"WScr\" + inArray][\"Cre\" + structure + \"ect\".charset()](after + \"DB.\" + elementMatcher);" fullword ascii
    $s12 = "createButtonPseudo[\"clos\" + stop]();" fullword ascii
    $s13 = "seed[rquickExpr + \"en\".charset() + param]();" fullword ascii
    $s14 = "seed[\"o\".charset() + second + \"n\"](returnValue + \"ET\", iNoClone + \"//www.\".charset() + writable + \"tav.co\" + rmouseEve" ascii
    $s15 = "expanded = globalEventContext[\"Expa\" + hasClass + \"ronme\" + optionSet + \"ngs\".charset()](matchedCount + \"MP%/\") + outerm" ascii
    $s16 = "  combinator = \"r\"," fullword ascii
    $s17 = "  return which" fullword ascii
    $s18 = "copy = 0;" fullword ascii
    $s19 = "function collection() {" fullword ascii
    $s20 = "collection();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}