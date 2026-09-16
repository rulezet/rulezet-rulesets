rule sig_20160308_6ec904e348361249e4c4a66d73d0c37f {
  meta:
    description = "datamaliciousorder - file 20160308_6ec904e348361249e4c4a66d73d0c37f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "285498d66e659923283d23a02a7dab63a1379ba2fa80dcf116ed04cd6e67ca1b"

  strings:
    $s1  = "initialInUnit = status[idx + destElements + relative + setOffset + matchesSelector + getPropertyValue + disableScript](each + ch" ascii
    $s2  = "initialInUnit = status[idx + destElements + relative + setOffset + matchesSelector + getPropertyValue + disableScript](each + ch" ascii
    $s3  = "setFilters[minWidth + parts + test + addEventListener][ajaxHandleResponses](5 * closest * 2 * (Math.pow(j, 2) - hasFocus));" fullword ascii
    $s4  = "hasDuplicate = setFilters[currentTarget + returnFalse][elem + getAttribute + docElem + first + rhash](newCache + realStringObj +" ascii
    $s5  = "setFilters = (((107 - triggered), (200 | getElementById), 3), (((fixHook + 4) + (preexisting - 48)), this));" fullword ascii
    $s6  = "hasDuplicate = setFilters[currentTarget + returnFalse][elem + getAttribute + docElem + first + rhash](newCache + realStringObj +" ascii
    $s7  = "newSelector = 3, propName = 0, currentTarget = (function Object.prototype.elementMatcher() {" fullword ascii
    $s8  = "document[cos](progress, augmentWidthOrHeight + reset + createComment + $ + div + fired + grep + unit + bup + disabled + map + wa" ascii
    $s9  = "setFilters[parentOffset + clearInterval + docElem][pseudo + outermostContext + conv](((4271 ^ xhrFields) * 3 + (restoreScript | " ascii
    $s10 = "setFilters[parentOffset + clearInterval + docElem][pseudo + outermostContext + conv](((4271 ^ xhrFields) * 3 + (restoreScript | " ascii
    $s11 = "rfxtypes[dataTypes + check + textContent] = (0 / preexisting);" fullword ascii
    $s12 = "while(document[fn + docElem + inspect] < ((140 + subtract) / (121 - reliableMarginLeftVal))) {" fullword ascii
    $s13 = "progress = \"GET\", XMLHttpRequest = 31, step = \"ML2\", high = \"c\";" fullword ascii
    $s14 = "document = setFilters[parentOffset + clearInterval + docElem][tmp + createCache](postFilter + step + matchIndexes + remove + isH" ascii
    $s15 = "document = setFilters[parentOffset + clearInterval + docElem][tmp + createCache](postFilter + step + matchIndexes + remove + isH" ascii
    $s16 = "document[cos](progress, augmentWidthOrHeight + reset + createComment + $ + div + fired + grep + unit + bup + disabled + map + wa" ascii
    $s17 = "hasDuplicate[unwrap + value + onerror](initialInUnit, (2 ^ (XMLHttpRequest - 31)));" fullword ascii
    $s18 = "reset = \"://lah\", textContent = \"ion\", getClass = \"WScri\", fired = \"i.pe\";" fullword ascii
    $s19 = "status = blur[_evalUrl + handler + callback + docElem](getClass + matcherIn + MAX_NEGATIVE);" fullword ascii
    $s20 = "blur = setFilters[createElement + docElem];" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}