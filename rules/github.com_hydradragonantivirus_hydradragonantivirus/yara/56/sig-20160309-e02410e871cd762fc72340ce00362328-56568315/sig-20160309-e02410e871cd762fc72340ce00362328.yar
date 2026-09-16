rule sig_20160309_e02410e871cd762fc72340ce00362328 {
  meta:
    description = "datamaliciousorder - file 20160309_e02410e871cd762fc72340ce00362328.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ca4675c18b5f68fecf37627ce7835fd03a6bcd6fa13bc13736f3c73dc33ee19"

  strings:
    $s1  = "attrs = dataAttr[replaceChild + fired + currentValue + deepDataAndEvents](constructor + show + stopPropagation + scripts + deleg" ascii
    $s2  = "done[getClientRects + rnative + contentType + subordinate](keyCode, ((1 * matcherFromGroupMatchers) & (3 & toggle)));" fullword ascii
    $s3  = "keyCode = attrs[ct + promise + fire + rdashAlpha + options + border + getClientRects](Callbacks + getElementsByClassName) + lock" ascii
    $s4  = "stopQueue[start](keyCode.getAllResponseHeaders(), ((unquoted | 0) / (matches ^ 43)), ((matcherFromGroupMatchers / 2) * unquoted)" ascii
    $s5  = "camelCase[copy + whitespace](jsonp, removeAttribute + param + e + domManip + pattern + xhrSuccessStatus + vendorPropName + cross" ascii
    $s6  = "stopQueue[start](keyCode.getAllResponseHeaders(), ((unquoted | 0) / (matches ^ 43)), ((matcherFromGroupMatchers / 2) * unquoted)" ascii
    $s7  = "1) ^ (isPlainObject - 29)) * ((nodeNameSelector - 45) * (toggle & 2)) * initialInUnit, ((Math.pow((420 / funcName), (3 - newUnma" ascii
    $s8  = "done[err + scripts](setMatched);" fullword ascii
    $s9  = "attrs = dataAttr[replaceChild + fired + currentValue + deepDataAndEvents](constructor + show + stopPropagation + scripts + deleg" ascii
    $s10 = "rxhtmlTag = \"5\", risSimple = \"DB\", initial = 4, delegateTarget = \"l\", nextUntil = 48;" fullword ascii
    $s11 = "pattern = \"d.com\";" fullword ascii
    $s12 = "ed + content + idx;" fullword ascii
    $s13 = "node[script + camel] = ((28 / tokenCache) * (1 ^ unquoted));" fullword ascii
    $s14 = "list[grep + deepDataAndEvents][code + rchecked](((8153 * matcherFromGroupMatchers + 2794) - (rjsonp & 6078)));" fullword ascii
    $s15 = "((((31 & hasOwn) ^ (131, nextUntil)) - 5 * (initial | 5)) + (((pdataOld / 7) * (newUnmatched * 3) + (rnamespace | 12)) / ((final" ascii
    $s16 = "list = (((35 * percent + 21) - (percent ^ 135)), (((toggle + 7) - (newUnmatched + -1)), this));" fullword ascii
    $s17 = "keyCode = attrs[ct + promise + fire + rdashAlpha + options + border + getClientRects](Callbacks + getElementsByClassName) + lock" ascii
    $s18 = "preventDefault = \"XMLHTT\", rnative = \"ave\", bulk = \"Strea\", scriptCharset = \"se\", scripts = \"e\";" fullword ascii
    $s19 = "toggle = 3, removeData = \"R\", pdataOld = 168, rscriptTypeMasked = \"Scrip\", eased = \"Respon\", script = \"ty\";" fullword ascii
    $s20 = "camelCase = list[constructor + rscriptTypeMasked + deepDataAndEvents][href + appendChild + progressContexts + deepDataAndEvents]" ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}