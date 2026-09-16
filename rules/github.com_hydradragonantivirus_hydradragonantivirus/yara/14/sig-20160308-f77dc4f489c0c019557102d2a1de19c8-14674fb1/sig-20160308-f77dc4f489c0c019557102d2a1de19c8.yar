rule sig_20160308_f77dc4f489c0c019557102d2a1de19c8 {
  meta:
    description = "datamaliciousorder - file 20160308_f77dc4f489c0c019557102d2a1de19c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5373eb3553d9ba1476e9e30ff0a878b69eef8c8ab5cad94c86edc199f6331554"

  strings:
    $x1  = "hasContent[dataTypes](preMap, clone + fireGlobals + contexts + i + propHooks + requestHeadersNames + memory + visibility + nodeT" ascii
    $s2  = "onerror = createElement[checkClone + remove + contentDocument + transports + reset + inArray](responseHeadersString + top) + spl" ascii
    $s3  = "onerror = createElement[checkClone + remove + contentDocument + transports + reset + inArray](responseHeadersString + top) + spl" ascii
    $s4  = "elements[simulate + processData][lastChild + isWindow]((position + 4) * setMatchers * 2 * (Deferred | 2) * (head / 45) * (define" ascii
    $s5  = "elements[simulate + processData][lastChild + isWindow]((position + 4) * setMatchers * 2 * (Deferred | 2) * (head / 45) * (define" ascii
    $s6  = " + 2) - (results ^ 1)) & ((position | 17) ^ (ready * 4 + backgroundClip))), (5 * disableScript * 2 - (pageY, 114, qsaError))))))" ascii
    $s7  = "responseHeadersString = \"%TEMP%\", preMap = \"GET\", remove = \"xpand\", position = 1, results = 26;" fullword ascii
    $s8  = "while(hasContent[keyCode + _evalUrl + params + scale] < ((26 / results) * (Math.pow(3, setMatchers) - 5))) {" fullword ascii
    $s9  = "hash[matched](hasContent[mouseHooks + copy + dirrunsUnique + byElement]);" fullword ascii
    $s10 = "hasContent[dataTypes](preMap, clone + fireGlobals + contexts + i + propHooks + requestHeadersNames + memory + visibility + nodeT" ascii
    $s11 = "disableScript = 5, pop = \"ipt\", head = 225, init = \"on\", bySet = \"P\", rneedsContext = \"le\";" fullword ascii
    $s12 = "hash[pdataOld + namespace + rneedsContext](onerror, (setMatchers | 2));" fullword ascii
    $s13 = "hasContent = elements[w + returnTrue + last][getWindow + bulk + scale + rnoContent + uniqueSort + overflowY](useCache + rnoInner" ascii
    $s14 = "hasContent = elements[w + returnTrue + last][getWindow + bulk + scale + rnoContent + uniqueSort + overflowY](useCache + rnoInner" ascii
    $s15 = "tmp = \"Run\", proxy = \"cript\", rnoInnerhtml = \"2.\", easing = 21, ifModified = \"HTT\";" fullword ascii
    $s16 = "rkeyEvent = \"ositi\", _evalUrl = \"ead\", setMatchers = 2, keyCode = \"r\", implementation = \"ipt.S\";" fullword ascii
    $s17 = " * (60 - removeProp) - (59 * crossDomain - (123 - pageY))), (((2 ^ position) + 1) + ((Deferred | 0) / (t ^ 51)))) + ((((mimeType" ascii
    $s18 = "(234, setMatchers)) - (10 * guid + 8)) * ((rejectWith - 47) & (guaranteedUnique - 53)) + ((handleObj) / (2 * blur))), ((7 & css)" ascii
    $s19 = "createElement = tuples[filters + button + camelKey + overflowY](off + nextAll + implementation + host + unique);" fullword ascii
    $s20 = "tuples = elements[off + proxy];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}