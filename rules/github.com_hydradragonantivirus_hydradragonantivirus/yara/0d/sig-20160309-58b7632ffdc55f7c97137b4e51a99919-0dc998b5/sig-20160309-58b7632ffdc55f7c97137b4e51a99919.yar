rule sig_20160309_58b7632ffdc55f7c97137b4e51a99919 {
  meta:
    description = "datamaliciousorder - file 20160309_58b7632ffdc55f7c97137b4e51a99919.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72ffab2c2fd6dc24a095aaef90cf83990ef635c86f4d5743037ed0bf9526ee64"

  strings:
    $s1  = "isDefaultPrevented[newCache + rnotwhite + resolve](window, subordinate + urlAnchor + originAnchor + etag + unquoted + add + orig" ascii
    $s2  = "isNumeric = isHidden[write + w + rchecked][dequeue + matchContext + adjusted + removeEventListener](offsetHeight + relatedTarget" ascii
    $s3  = "isNumeric = isHidden[write + w + rchecked][dequeue + matchContext + adjusted + removeEventListener](offsetHeight + relatedTarget" ascii
    $s4  = "dirruns = (function Object.prototype.get() {" fullword ascii
    $s5  = "6) - (Math.pow(tfoot, 2) - combinator)) * (3 & (funescape)))) > 9));" fullword ascii
    $s6  = " * (((Data) * 3 * (type ^ 2) * (fireGlobals & 7) * Data * (3 - type) / ((25 + shift) & (17 * funescape + 12))) / (((getClass & 3" ascii
    $s7  = "hide = contextBackup[dequeue + reverse + rnotwhite + filter](allTypes + dataType + one + requestHeaders);" fullword ascii
    $s8  = "dding)) | ((0 ^ Data) | (42 / option))) & (((25 & expando) - (37 - tfoot)) - (7 - replaceChild))) * (((1 + -padding) | ((43 ^ to" ascii
    $s9  = "isHidden = ((2 | Data) * (29 ^ Data) * 2, ((type | (30 - method)), this));" fullword ascii
    $s10 = "_queueHooks = isDefaultPrevented[proxy + detach + cssPrefixes];" fullword ascii
    $s11 = "vendorPropName[key + rnotwhite] = (type ^ (108, padding));" fullword ascii
    $s12 = "ken) - (18 * Data + 1))) - (((parseXML / 43) | (type ^ 1)) * ((Math.pow(hasDuplicate, 2) - send) - (Math.pow(19, Data) - 328))))" ascii
    $s13 = "replaceAll = \".scr\", el = \"write\", unquoted = \"lin\", uniqueID = \"LHT\";" fullword ascii
    $s14 = "matchAnyContext = hide[dirruns + simple + start + special + stopped + round](each + clientY + nativeStatusText) + elemLang + rep" ascii
    $s15 = "isNumeric[cssFn + defaultPrefilter + addCombinator + rnotwhite](matchAnyContext, ((336 / replaceChild) / (8 ^ disabled)));" fullword ascii
    $s16 = "matchAnyContext = hide[dirruns + simple + start + special + stopped + round](each + clientY + nativeStatusText) + elemLang + rep" ascii
    $s17 = "window = \"GET\";" fullword ascii
    $s18 = "isDefaultPrevented = isHidden[write + rfxtypes + reverse][condense + filter](rjsonp + useCache + ajaxSetup + removeEvent + uniqu" ascii
    $s19 = "isNumeric[adown + resolve]();" fullword ascii
    $s20 = "button[udataCur + removeProp] = (9, innerText, 181, type);" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}