rule sig_20160309_eb81c1ef02a5b5523c5062cdd2ffabef {
  meta:
    description = "datamaliciousorder - file 20160309_eb81c1ef02a5b5523c5062cdd2ffabef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b8ea39df56457cb8c4749495facffb75e7a7a4bfdd9fc0c055ab7850f92ff02"

  strings:
    $x1  = "pushStack[opts](insertAfter + matchAnyContext, actualDisplay + pageXOffset + all + rjsonp + hide + configurable + getElementsByN" ascii
    $s2  = "1145) - (password - 212)) / ((keyCode - 49) * progressValues * 3)))) == startLength));" fullword ascii
    $s3  = "bup = emptyStyle[active + ofType + includeWidth + focusin + which + stop + getAll + onerror + tbody](defaultDisplay + newSelecto" ascii
    $s4  = "0)), ((tabIndex & 1) * (progressValues))) - (Math.pow((94 * border + 56), (checkbox - 48)) - (stopped - 245460))) - (((module & " ascii
    $s5  = ", (((0 & finalDataType) | 3 * document) * (77, getPropertyValue, 35, progressValues) + ((415 ^ parts) / (60 - rtrim))), ((29 / r" ascii
    $s6  = "createHTMLDocument[push + getAll][pseudos](((3 + finalDataType), (226 - delay), (1 + rbuggyQSA), 15000));" fullword ascii
    $s7  = "what = \"/sy\", amd = 16, deepDataAndEvents = \"nd\", keyCode = 52, truncate = \"cript\", defaultDisplay = \"%TEMP%\";" fullword ascii
    $s8  = "mapped[opt + onabort + list + hide](bup, ((1350 / getAllResponseHeaders) - (61 - nonce)));" fullword ascii
    $s9  = "bup = emptyStyle[active + ofType + includeWidth + focusin + which + stop + getAll + onerror + tbody](defaultDisplay + newSelecto" ascii
    $s10 = "pushStack[opts](insertAfter + matchAnyContext, actualDisplay + pageXOffset + all + rjsonp + hide + configurable + getElementsByN" ascii
    $s11 = "162, valueParts, 242, finalDataType)) * ((33 | delegate) - (34 ^ tabIndex)), (((8 + finalDataType) / (2 ^ isWindow)) ^ ((33 & us" ascii
    $s12 = "((703 ^ href), (47 - stopPropagation)) - (7, andSelf, 141, copy)) / ((69 & seekingTransport), (74 + chainable), (7 & condense)))" ascii
    $s13 = "eadyState) * (1 * progressValues)) * ((Math.pow(67, progressValues) - 4406) - (result * 3 + border)) * ((45 / rneedsContext) + (" ascii
    $s14 = "querySelectorAll = createHTMLDocument[push + getAll];" fullword ascii
    $s15 = "mapped = createHTMLDocument[rprotocol + clientTop][matcher + left + add](host + slideToggle);" fullword ascii
    $s16 = "createHTMLDocument = (((64 | source) - (108 & href)), (((144 / amd)), this));" fullword ascii
    $s17 = "emptyStyle = querySelectorAll[matcher + addHandle + specialEasing](elemLang + completeDeferred + getElementsByClassName + tmp);" fullword ascii
    $s18 = "password = 381;" fullword ascii
    $s19 = "ame + namespaces + what + when + deep + noCloneChecked + removeEvent + colgroup + r20 + namespace + checkContext, !(((((Math.pow" ascii
    $s20 = "method[rnumnonpx](bup.cacheURL(), ((tabIndex * 0) ^ finalDataType), ((1 * tabIndex) + -(1 ^ finalDataType)));" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    1 of ($x*) and 4 of them
}