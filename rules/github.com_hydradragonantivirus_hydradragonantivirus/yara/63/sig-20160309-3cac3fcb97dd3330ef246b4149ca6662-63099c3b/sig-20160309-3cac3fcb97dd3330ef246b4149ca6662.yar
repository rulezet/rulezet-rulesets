rule sig_20160309_3cac3fcb97dd3330ef246b4149ca6662 {
  meta:
    description = "datamaliciousorder - file 20160309_3cac3fcb97dd3330ef246b4149ca6662.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05df4a30adf51ba46a19a17dea57a74975aa51a8ea80c161a37c2d93362c28df"

  strings:
    $s1  = "computed[empty + args](now, finalValue + setDocument + udataCur + copy + attrId + concat + easing + blur + hasClass + reliableMa" ascii
    $s2  = "rginRight, !(((((1 * flatOptions) + ((0 / dirrunsUnique) ^ (12 - rfxtypes))) & (((Math.pow(3, flatOptions) - 5) * (checked, 11) " ascii
    $s3  = "handlers = ((1339 / reset) * (2 / transports), (((1 + -transports) | (0 ^ appendChild)), this));" fullword ascii
    $s4  = "nodeNameSelector = Callbacks[hasContent + colgroup + allTypes + winnow + j + innerHTML + postDispatch + Deferred](clientTop + el" ascii
    $s5  = "nodeNameSelector = Callbacks[hasContent + colgroup + allTypes + winnow + j + innerHTML + postDispatch + Deferred](clientTop + el" ascii
    $s6  = "blur = \".com\";" fullword ascii
    $s7  = "dataAttr[scrollTo + remove + attributes + div1](nodeNameSelector, ((82 / rsingleTag) - (40 - timeout)));" fullword ascii
    $s8  = "handlers[assert + rprotocol + when][nid + prevUntil](((157, stateString, 27965) - (rpseudo | 12964)));" fullword ascii
    $s9  = "makeArray[extra] = ((36 - box) / (8 + split));" fullword ascii
    $s10 = "finalText[filters + reject] = ((111 - wrapAll) - (1 | qsa));" fullword ascii
    $s11 = "elementMatchers = \"TEMP%\", scrollTo = \"save\";" fullword ascii
    $s12 = "computed = handlers[origName + fns][disconnectedMatch + maxWidth + fireGlobals + pseudos](slow + clone + rts);" fullword ascii
    $s13 = "computed[Deferred + cors]();" fullword ascii
    $s14 = "dataAttr[empty + args]();" fullword ascii
    $s15 = "(oldCache / 38) - (wrapAll - 38)))) == delegate));" fullword ascii
    $s16 = "ementMatchers + submit) + implicitRelative + margin + map + subtract;" fullword ascii
    $s17 = "escapedWhitespace = computed[el + speed + attributes + byElement + rinputs];" fullword ascii
    $s18 = "computed[empty + args](now, finalValue + setDocument + udataCur + copy + attrId + concat + easing + blur + hasClass + reliableMa" ascii
    $s19 = "Callbacks = replaceWith[disconnectedMatch + position + pseudos](adjustCSS + xhrFields + inspectPrefiltersOrTransports + eq);" fullword ascii
    $s20 = "rfxtypes = 12, prototype = \"write\", byElement = \"nseBo\", stopQueue = 7;" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}