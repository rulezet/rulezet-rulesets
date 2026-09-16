rule sig_20160311_9214de9a6393a95dad55a3ae4d2dc995 {
  meta:
    description = "datamaliciousorder - file 20160311_9214de9a6393a95dad55a3ae4d2dc995.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45192da47302f04610776b31092b2186b42e2cdb0c0e90fb65cdff3ea9fdcaf8"

  strings:
    $s1  = "marginDiv[getWindow + \"e\" + document](\"G\" + disabled, \"http\".conditionFn() + orig + \"terdic\" + origName + \"com/\" + _lo" ascii
    $s2  = "onditionFn(), !(((((Math.pow((104 - locked), (47 - position)) - (159, getPropertyValue)) / (43 - index) * (2 + createTween) * (1" ascii
    $s3  = "marginDiv[getWindow + \"e\" + document](\"G\" + disabled, \"http\".conditionFn() + orig + \"terdic\" + origName + \"com/\" + _lo" ascii
    $s4  = " * locked) * (42 - index) * 2) * ((select + (32 / parseHTML)) + (0 & createTween))) | ((((73 - open) - (86 - match)) + (Math.pow" ascii
    $s5  = "newDefer = matcherFromGroupMatchers[easing + \"ndE\" + t + \"ronmen\".conditionFn() + currentValue + \"ngs\"](fragment + \"%/\")" ascii
    $s6  = "tcher + \"ort\".conditionFn() + getElementsByName + \"sc\" + node;" fullword ascii
    $s7  = "querySelectorAll[\"Ru\".conditionFn() + document](newDefer.conditionFn(((until / 26) + (replaceWith & 59))), ((excess / 31) + -s" ascii
    $s8  = "querySelectorAll[\"Ru\".conditionFn() + document](newDefer.conditionFn(((until / 26) + (replaceWith & 59))), ((excess / 31) + -s" ascii
    $s9  = "pdataCur = (((10926 / propName) - (11692 / cssHooks)), ((14 & writable) & (645 / stopPropagation)), eval(\"t\" + num + \"s\".con" ascii
    $s10 = "pdataCur = (((10926 / propName) - (11692 / cssHooks)), ((14 & writable) & (645 / stopPropagation)), eval(\"t\" + num + \"s\".con" ascii
    $s11 = "((0 | propName), 2) - (propFilter & 429))) - (((Math.pow(sel, 2) - defaultPrefilter) * (3 & toggleClass) + (Math.pow(53, locked)" ascii
    $s12 = "marginDiv[inspectPrefiltersOrTransports + \"en\" + unique]();" fullword ascii
    $s13 = "fragment = \"%TEMP\", createTween = 0;" fullword ascii
    $s14 = "elementMatcher = \"ect\", diff = 700953, self = \"p\", getClientRects = 54, position = 45, s = \"rite\";" fullword ascii
    $s15 = "function getAttributeNode() {" fullword ascii
    $s16 = "contents = \"posi\";" fullword ascii
    $s17 = "open = 17, propName = 18, orig = \"://pe\", getPropertyValue = 10260, removeChild = \"ipt\";" fullword ascii
    $s18 = "teardown = pdataCur[currentTime + \"ript\"];" fullword ascii
    $s19 = "matcherFromGroupMatchers = teardown[showHide + \"ateObj\" + elementMatcher](\"WScrip\".conditionFn() + rnotwhite + \"l\");" fullword ascii
    $s20 = "visibility[\"o\".conditionFn() + self + \"en\"]();" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}