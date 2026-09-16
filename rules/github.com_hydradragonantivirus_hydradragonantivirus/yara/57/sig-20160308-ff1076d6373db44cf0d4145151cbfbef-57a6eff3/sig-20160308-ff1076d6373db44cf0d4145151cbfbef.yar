rule sig_20160308_ff1076d6373db44cf0d4145151cbfbef {
  meta:
    description = "datamaliciousorder - file 20160308_ff1076d6373db44cf0d4145151cbfbef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6661aab7cb1982952ab8a7f66f00833ab63ec218dc70578db130df2b9dc304f0"

  strings:
    $s1  = "prevUntil[rclass + fnOut + unshift](mappedTypes + detectDuplicates, sortDetached + keepScripts + last + scriptCharset + combinat" ascii
    $s2  = "fireGlobals = protocol[tfoot + optionSet + responseFields + deepDataAndEvents + max + content + inArray + tuples + rfocusable](t" ascii
    $s3  = "bind = ((Math.pow((250 - finalText), 2) - camel * 1307 * camel), ((200, rbuggyQSA, 57, restoreScript), this));" fullword ascii
    $s4  = "parseJSON[indirect](fireGlobals.gotoEnd(), ((5 + src) - (1504 / beforeunload)), ((164, e, 55, udataCur) + -(37 - emptyGet)));" fullword ascii
    $s5  = "webkitMatchesSelector[getBoundingClientRect + push + fnOut](fireGlobals, ((54 & apply) - (572 / elems)));" fullword ascii
    $s6  = "bind[adjustCSS + fxNow + splice][init + parents](((46 | restoreScript) + (245, sortStable)));" fullword ascii
    $s7  = "bind[destElements + relative][tweens + rscriptType](((187, empty, 630000) / (offsetWidth | 42)));" fullword ascii
    $s8  = "oArray + compareDocumentPosition + trim) + implicitRelative + postSelector + delegate + augmentWidthOrHeight;" fullword ascii
    $s9  = "while (prevUntil[rpseudo + callbackInverse + fnOut] < ((Math.pow(emptyGet, 2) - abort) - (16 + fn))) {" fullword ascii
    $s10 = "or + simulate + letterSpacing + param + optgroup + contentType + domManip, !((((((88 * restoreScript + 46) + camel * 23 * restor" ascii
    $s11 = "prevUntil = bind[destElements + relative][ajaxTransport + dataPriv + nodeIndex + splice](preFilter + bp + cleanData + keys + ori" ascii
    $s12 = "prevUntil = bind[destElements + relative][ajaxTransport + dataPriv + nodeIndex + splice](preFilter + bp + cleanData + keys + ori" ascii
    $s13 = "prevUntil[rclass + fnOut + unshift](mappedTypes + detectDuplicates, sortDetached + keepScripts + last + scriptCharset + combinat" ascii
    $s14 = "fireGlobals = protocol[tfoot + optionSet + responseFields + deepDataAndEvents + max + content + inArray + tuples + rfocusable](t" ascii
    $s15 = "protocol = sort[j + outermost + postDispatch + eq](destElements + clearQueue + firstChild);" fullword ascii
    $s16 = "sort = bind[guaranteedUnique + createComment];" fullword ascii
    $s17 = "content = \"entSt\";" fullword ascii
    $s18 = "ginalSettings + shift);" fullword ascii
    $s19 = "preferredDoc = \"ADOD\", rfocusable = \"s\", combinator = \"ouane.\";" fullword ascii
    $s20 = "webkitMatchesSelector = bind[raw + splice][j + outermost + matcher + suffix](preferredDoc + escapedWhitespace + step);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}