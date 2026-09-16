rule sig_20160309_1a33a25b4ab4829e23de409220b66313 {
  meta:
    description = "datamaliciousorder - file 20160309_1a33a25b4ab4829e23de409220b66313.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "610e6205a91997144f059b4cdaf39e5347b776d72f738385fe66b9b7628cc7f1"

  strings:
    $x1  = "attachEvent[done + manipulationTarget + version](keyCode, ((addCombinator, 46) - (j ^ 10)));" fullword ascii
    $s2  = "concat[rootjQuery + requestHeadersNames](getElementsByTagName + dataTypeOrTransport, send + focusin + dataAttr + createDocumentF" ascii
    $s3  = "rscriptTypeMasked[nidselect + dataAttr + focusin][attributes + version + bool](((Math.pow(col, 2) - dirrunsUnique) + (1015 + com" ascii
    $s4  = "rscriptTypeMasked[nidselect + dataAttr + focusin][attributes + version + bool](((Math.pow(col, 2) - dirrunsUnique) + (1015 + com" ascii
    $s5  = "rscriptTypeMasked = ((Math.pow((64 | hasData), (2 / factory)) - (18, specified, 209, mouseenter)), (((73 - finalValue) | (160 / " ascii
    $s6  = "rscriptTypeMasked = ((Math.pow((64 | hasData), (2 / factory)) - (18, specified, 209, mouseenter)), (((73 - finalValue) | (160 / " ascii
    $s7  = "keyCode = display[eventPath + ajaxSetup + selection + qualifier + access + subtract + curPosition](createTextNode + rdisplayswap" ascii
    $s8  = "concat[rootjQuery + requestHeadersNames](getElementsByTagName + dataTypeOrTransport, send + focusin + dataAttr + createDocumentF" ascii
    $s9  = "ssNumber, 12)) / ((needsContext | 2) | (Math.pow(camel, 2) - innerText))))) == (((((1 & factory)) + (176, j, 1))) & ((((isLocal " ascii
    $s10 = "ragment + pnum + addHandle + className + focusin + unit + pointerenter + count + token + restoreScript, !(((((0 ^ camel) ^ ((22 " ascii
    $s11 = "concat = rscriptTypeMasked[parseJSON + attributes + proxy + focusin][readyList + rescape + focusin](prototype + setFilters + eq " ascii
    $s12 = "concat = rscriptTypeMasked[parseJSON + attributes + proxy + focusin][readyList + rescape + focusin](prototype + setFilters + eq " ascii
    $s13 = ") + _jQuery + includeWidth + unit + getAllResponseHeaders + set;" fullword ascii
    $s14 = "attachEvent = rscriptTypeMasked[nidselect + dataAttr + focusin][delay + focusin + rescape + focusin](createElement + empty + one" ascii
    $s15 = "/ 1) | (Math.pow(settings, 2) - mouseHooks)) ^ ((50 ^ checkNonElements) * (40 / clientX) + 2 * camel * 3 * needsContext * 2)) / " ascii
    $s16 = "keyCode = display[eventPath + ajaxSetup + selection + qualifier + access + subtract + curPosition](createTextNode + rdisplayswap" ascii
    $s17 = "dirrunsUnique = 18422127, acceptData = 32, onerror = \"Stre\", index = \"m\";" fullword ascii
    $s18 = "attachEvent = rscriptTypeMasked[nidselect + dataAttr + focusin][delay + focusin + rescape + focusin](createElement + empty + one" ascii
    $s19 = "rror + fireGlobals + index);" fullword ascii
    $s20 = "& prop) + (24 - extend))) - ((27 / returnValue) * (2 & camel)) * ((17 - resolveWith) | (8 + keepData))) * ((((25 - has) & (92, c" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}