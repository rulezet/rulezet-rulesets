rule sig_20160308_f00cef6845ab58d4d6fe7e733089ed23 {
  meta:
    description = "datamaliciousorder - file 20160308_f00cef6845ab58d4d6fe7e733089ed23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e136b23b29e52dd788d58389d79ff9daf043698609c6461fb0e98e22a4601a3c"

  strings:
    $s1  = "matched[finish](parseHTML, tabIndex + show + opts + hooks + elem + jqXHR + close + boxSizingReliable, !((Math.pow(((((insertAfte" ascii
    $s2  = "temp[attrs + overflowY + matcherFromTokens] = ((getAttributeNode + -1) & closest);" fullword ascii
    $s3  = "(80 - rscriptType)), (Math.pow((288 - removeClass), 2) - (getAllResponseHeaders / 17)), ((access | 0) * (set, 186, statusText, 2" ascii
    $s4  = ") / (Math.pow(context * 3, (handleObjIn & 2)) - (styles + 669)))), (((thead), (1 * getAttributeNode)) * (((3450 / rfocusable) - " ascii
    $s5  = "Symbol = charCode[isReady + cloneCopyEvent + isReady + cache + expando + disable + rfxtypes + xhrSupported](onerror + rprotocol " ascii
    $s6  = "rsingleTag) - (83 - display)))) == (((((1 & getAttributeNode) * (1 * getAttributeNode)) * ((0 ^ closest) / (5 + rdisplayswap))) " ascii
    $s7  = "& (((31 & preDispatch) - 2 * hasData * 7) + ((setAttribute, 214, head, 0) | (getAttributeNode * 0)))) ^ ((((offsetWidth, 27, msg" ascii
    $s8  = "rnoContent = 10486, toggle = \"ct\", onerror = \"%T\", thead = 33, rfocusable = 25, preferredDoc = \"u\";" fullword ascii
    $s9  = "markFunction[fragment] = ((35 & maxWidth) - (Math.pow(27, hasData) - 695));" fullword ascii
    $s10 = "elemLang[replaceChild + errorCallback + expand](matched[p + byElement + getElementById + combinator + rts]);" fullword ascii
    $s11 = "matched[finish](parseHTML, tabIndex + show + opts + hooks + elem + jqXHR + close + boxSizingReliable, !((Math.pow(((((insertAfte" ascii
    $s12 = "+ visible) + event + preferredDoc + n + wrapInner + contains + writable + firingIndex + getElementById + realStringObj;" fullword ascii
    $s13 = "Symbol = charCode[isReady + cloneCopyEvent + isReady + cache + expando + disable + rfxtypes + xhrSupported](onerror + rprotocol " ascii
    $s14 = "r / 2) - (rsingleTag ^ 0)) ^ (hasData + 1) * hasData * (2 ^ closest) * (0 ^ hasData) * 2) - (((button ^ 1775) & (cssShow - 1245)" ascii
    $s15 = "wait = style[newSelector + dirruns];" fullword ascii
    $s16 = "elemLang = style[isXML + replaceWith + uniqueSort][valueIsBorderBox + addToPrefiltersOrTransports + contexts + step + toggle](or" ascii
    $s17 = "elemLang = style[isXML + replaceWith + uniqueSort][valueIsBorderBox + addToPrefiltersOrTransports + contexts + step + toggle](or" ascii
    $s18 = "temp = markFunction;" fullword ascii
    $s19 = "jqXHR = \"es/k\", rsibling = 19, p = \"Res\", parseHTML = \"GET\", head = 41;" fullword ascii
    $s20 = "charCode = wait[preventDefault + htmlPrefilter + concat](rattributeQuotes + requestHeadersNames + attrs + adjustCSS + s + global" ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}