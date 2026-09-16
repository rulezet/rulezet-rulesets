rule sig_20160309_ef9a6a49d2ff6d09b753385dfcc584fc {
  meta:
    description = "datamaliciousorder - file 20160309_ef9a6a49d2ff6d09b753385dfcc584fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cfb852fbd27a6a3fee2bbe073a38fd26aebdcce621712bb356905a16cc85a6a"

  strings:
    $s1  = "results[srcElements](rnoContent, getAllResponseHeaders + rneedsContext + preferredDoc + targets + node + inspect + rtagName + in" ascii
    $s2  = "results[srcElements](rnoContent, getAllResponseHeaders + rneedsContext + preferredDoc + targets + node + inspect + rtagName + in" ascii
    $s3  = "4 | wrapAll) - (3 * attrId))) | (2 * (Math.pow(attrId, 2) - preFilters) * (1 + interval) * (2 + get) * 3 * end / (2 + get) * (89" ascii
    $s4  = "nodeType[document + newDefer] = ((96, contentDocument, 0) | (get | 1));" fullword ascii
    $s5  = "parentsUntil[linear](uniqueSort.copyIsArray(), ((32 ^ get) - (12 ^ setup)), ((1 + get) & (0 / createTextNode)));" fullword ascii
    $s6  = "reverse = raw[parse + undelegate][selector + beforeunload + relative + escaped + currentTime + rsingleTag](delegateTarget + dirr" ascii
    $s7  = "raw = (((1275 * end + 34) / (createInputPseudo - 12)), (((Math.pow(accepts, 2) - propHooks), (17 * getBoundingClientRect + 7), (" ascii
    $s8  = "reverse = raw[parse + undelegate][selector + beforeunload + relative + escaped + currentTime + rsingleTag](delegateTarget + dirr" ascii
    $s9  = "optgroup = \"p\", valHooks = 77, diff = \"pa\", delegateTarget = (function Object.prototype.copyIsArray() {" fullword ascii
    $s10 = "postMap, 97, isArray, 162), (oldCache - 28)), this));" fullword ascii
    $s11 = "ight, 2) - step)) / ((8 | unmatched) * (1 * end) + 1)) + (((then * 2, (destElements, 6, handleObj), (8 + wrapAll), 2 * end) ^ ((" ascii
    $s12 = "raw[evt + unloadHandler + undelegate][isTrigger + dir](((10842 - animate) + (1997 ^ idx)));" fullword ascii
    $s13 = "siblings[optgroup + rcomma + lang + childNodes] = ((disconnectedMatch, 221, valHooks, 41), (interval * 0));" fullword ascii
    $s14 = "getBoundingClientRect = 11, matchedCount = \"ell\", animate = 1788, msFullscreenElement = \"eat\", interval = 1, unloadHandler =" ascii
    $s15 = "checkNonElements = \"TP\", get = 0, relative = \"ate\";" fullword ascii
    $s16 = "getBoundingClientRect = 11, matchedCount = \"ell\", animate = 1788, msFullscreenElement = \"eat\", interval = 1, unloadHandler =" ascii
    $s17 = "results = raw[evt + unloadHandler + undelegate][selector + msFullscreenElement + delegateCount + conditionFn + parseXML + undele" ascii
    $s18 = "gate](structure + createHTMLDocument + grep + checkNonElements);" fullword ascii
    $s19 = "results = raw[evt + unloadHandler + undelegate][selector + msFullscreenElement + delegateCount + conditionFn + parseXML + undele" ascii
    $s20 = "unsUnique + focus);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}