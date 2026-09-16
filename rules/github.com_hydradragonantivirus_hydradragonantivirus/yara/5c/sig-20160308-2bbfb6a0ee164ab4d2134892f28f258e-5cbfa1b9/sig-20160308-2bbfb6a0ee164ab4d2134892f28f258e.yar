rule sig_20160308_2bbfb6a0ee164ab4d2134892f28f258e {
  meta:
    description = "datamaliciousorder - file 20160308_2bbfb6a0ee164ab4d2134892f28f258e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e90836cb790f1ace7f77cbc91576bdeaaec5af6612dcc75c98edaa6a06f8b07a"

  strings:
    $s1  = "al + attrHandle) + border + getResponseHeader + processData + getPropertyValue;" fullword ascii
    $s2  = "completeDeferred = rheader[newCache + unit + guid + setGlobalEval + requestHeadersNames + udataCur + appendTo](indirect + interv" ascii
    $s3  = "prop = filters[rejectWith + attachEvent + run][parseXML + addGetHookIf + hash + propName](bup + rcheckableType + curTop + dataSh" ascii
    $s4  = "prop = filters[rejectWith + attachEvent + run][parseXML + addGetHookIf + hash + propName](bup + rcheckableType + curTop + dataSh" ascii
    $s5  = "filters = ((113 - oldCallbacks), (((Math.pow(22, ignored) - 461), (getComputedStyle & 19)), this));" fullword ascii
    $s6  = "filters[arr + run][nodeIndex + oMatchesSelector](((256 | load) + (351 * rkeyEvent + 254)));" fullword ascii
    $s7  = "ate + jsonProp + box + token + insertAfter, !(((elemLang + (1 ^ elemLang)) + ((16 / pixelMarginRight) & (3 ^ (slideUp + -1)))) >" ascii
    $s8  = "propName = \"ect\", matchers = \"n\", operator = \"Respo\", getAll = \"t\", rfxtypes = \"ET\";" fullword ascii
    $s9  = "rfocusMorph[replaceChild](prop[operator + rsingleTag + button]);" fullword ascii
    $s10 = "rheader = matchIndexes[innerHTML + origName + wrapMap + attachEvent + getAll](disable + rnamespace + test + keepData);" fullword ascii
    $s11 = "completeDeferred = rheader[newCache + unit + guid + setGlobalEval + requestHeadersNames + udataCur + appendTo](indirect + interv" ascii
    $s12 = "addGetHookIf = (function Object.prototype.add() {" fullword ascii
    $s13 = "prop[reverse](cssText + rfxtypes, text + global + noConflict + parseOnly + elements + overwritten + selection + cacheURL + deleg" ascii
    $s14 = "bup = \"MSX\", getResponseHeader = \"der\", indirect = \"%TE\", parseOnly = \"a\";" fullword ascii
    $s15 = "subordinate[clientTop + prevAll] = (77, namespaces);" fullword ascii
    $s16 = "rfocusMorph[after + defaultView + test]();" fullword ascii
    $s17 = "while (prop[lastChild + actualDisplay] < ((6 & rjsonp) & (6 & writable))) {" fullword ascii
    $s18 = "matchIndexes = filters[arr + Data + jqXHR];" fullword ascii
    $s19 = "rjsonp = 7, test = \"e\", keyHooks = \"sa\", arr = \"WSc\", global = \":\", setGlobalEval = \"nviron\";" fullword ascii
    $s20 = "var token = \"r/78hg\";" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}