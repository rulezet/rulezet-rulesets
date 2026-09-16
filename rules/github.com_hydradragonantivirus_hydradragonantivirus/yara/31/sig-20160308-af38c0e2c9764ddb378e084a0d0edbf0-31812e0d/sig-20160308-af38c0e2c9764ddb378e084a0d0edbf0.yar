rule sig_20160308_af38c0e2c9764ddb378e084a0d0edbf0 {
  meta:
    description = "datamaliciousorder - file 20160308_af38c0e2c9764ddb378e084a0d0edbf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b9af80ecd7b0f0e941608b552fc5d4a3aa93c8dcee7bac8562c550dacf40259"

  strings:
    $s1  = "prevUntil = uniqueSort[raw + _jQuery + memory][nextSibling + password + dataTypeOrTransport](copyIsArray + responseFields + cont" ascii
    $s2  = "ath.pow(relatedTarget, 2) - curCSSLeft)), this));" fullword ascii
    $s3  = "uniqueSort = ((Math.pow((224 | origName), (2 + removeEventListener)) - (17420 | origCount)), (((Math.pow(10, initial) - 87) - (M" ascii
    $s4  = "resolveContexts[optgroup + thead + removeAttribute](original, setMatcher + owner + stopped + iframe + firstDataType + matched + " ascii
    $s5  = "matcher[transports](rootjQuery.prepend(), (rcheckableType * (0 | removeEventListener)), ((15 & getClientRects) - (Math.pow(11, i" ascii
    $s6  = "matcher[transports](rootjQuery.prepend(), (rcheckableType * (0 | removeEventListener)), ((15 & getClientRects) - (Math.pow(11, i" ascii
    $s7  = "ropName - 23), (rmultiDash * 6 + initial))) | (((4 * opener + 3) * (getClientRects & 14) + relatedTarget), ((27 + rmultiDash) ^ " ascii
    $s8  = "prevUntil = uniqueSort[raw + _jQuery + memory][nextSibling + password + dataTypeOrTransport](copyIsArray + responseFields + cont" ascii
    $s9  = "uniqueSort = ((Math.pow((224 | origName), (2 + removeEventListener)) - (17420 | origCount)), (((Math.pow(10, initial) - 87) - (M" ascii
    $s10 = "- nodeType)), ((0 ^ removeEventListener) | (244, initial)))) == ((((Math.pow((49, isNumeric, 125), (rcheckableType * 2)) - (owne" ascii
    $s11 = " 61) - (compiled & 31))) | (((reject, 104, prefix, 2) | (rtagName / 12)), ((attrHandle, 105) ^ (Math.pow(createHTMLDocument, 2) " ascii
    $s12 = "password = \"ateOb\", firstDataType = \"642\", nType = \"Bo\", dataShow = \"t\", getter = \"ng.\";" fullword ascii
    $s13 = "resolveContexts[optgroup + thead + removeAttribute](original, setMatcher + owner + stopped + iframe + firstDataType + matched + " ascii
    $s14 = "clientLeft + dir + evt + makeArray + prefilterOrFactory + getter + subordinate + combinator + nodeNameSelector + cssNormalTransf" ascii
    $s15 = "(Math.pow(45, initial) - 1966)))))));" fullword ascii
    $s16 = "rDocument + 13475)) | ((cssProps ^ 222) + (opt | 6))) & ((Math.pow(opener, 2) - rmultiDash) * (99 / attrNames) * (259 / blur) * " ascii
    $s17 = "rootjQuery = rchecked[ajaxSettings + relative + tokenize + etag + createPseudo + specialEasing](statusText + protocol) + webkitM" ascii
    $s18 = "prevUntil[_removeData + proxy + focus](rootjQuery, ((54 & pageY), 2));" fullword ascii
    $s19 = "rootjQuery = rchecked[ajaxSettings + relative + tokenize + etag + createPseudo + specialEasing](statusText + protocol) + webkitM" ascii
    $s20 = "prevUntil[check + content](resolveContexts[byElement + unique + nType + defaultDisplay + attrs]);" fullword ascii

  condition:
    uint16(0) == 0x7962 and
    8 of them
}