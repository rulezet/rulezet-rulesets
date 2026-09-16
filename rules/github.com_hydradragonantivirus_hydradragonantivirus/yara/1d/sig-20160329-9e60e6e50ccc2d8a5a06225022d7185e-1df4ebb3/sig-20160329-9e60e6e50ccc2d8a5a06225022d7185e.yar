rule sig_20160329_9e60e6e50ccc2d8a5a06225022d7185e {
  meta:
    description = "datamaliciousorder - file 20160329_9e60e6e50ccc2d8a5a06225022d7185e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "947865c74bd10252b08fc51a9c3ca0da9ae23583c24fa4891226468ea0b8ad01"

  strings:
    $s1  = "toSelector(\"animated%28rrun%20+%20%22//corr%22%20+%20qsaError%20+%20%22verd%22%20+%20grep%20+%20%22.com%22%20+%20unshift%20+%20" ascii
    $s2  = "toSelector(\"animated%28rrun%20+%20%22//corr%22%20+%20qsaError%20+%20%22verd%22%20+%20grep%20+%20%22.com%22%20+%20unshift%20+%20" ascii
    $s3  = "toSelector(\"while%20%28easing%5Berr%20+%20%22tat%22%20+%20results%5D%20%21%3D%20%28%282%26scriptCharset%29+2%29%29%20option%5B%" ascii
    $s4  = "targets(qualifier, isSuccess, tuples);" fullword ascii
    $s5  = "function toSelector(target) {" fullword ascii
    $s6  = "function targets(adown, src, cos) {" fullword ascii
    $s7  = "return matcherFromTokens(unescape(target));" fullword ascii
    $s8  = "if (easing[before + \"tatus\"] == ((12 - reliableMarginLeftVal) * (235 / wrapMap) * (1 * radio) * (5 & refElements) * 2)) {" fullword ascii
    $s9  = "for (unmatched = ((refElements + 17) - (until / 46)); unmatched < addBack[\"le\" + find]; unmatched++) {" fullword ascii
    $s10 = "push[\"WScr\" + success][\"Sl\" + rCRLF](((Math.pow(byElement, 2) - setMatchers) + (3829 & rts)));" fullword ascii
    $s11 = "removeAttribute[\"SaveTo\" + rnumnonpx](compile, (rfxtypes * 2));" fullword ascii
    $s12 = "webkitMatchesSelector[\"R\" + rhtml](compile);" fullword ascii
    $s13 = "easing = push[\"WScr\" + success][\"Create\" + combinator + \"t\"](addBack[unmatched]);" fullword ascii
    $s14 = "toSelector(\"easing%5Bname%20+%20%22e%22%20+%20conditionFn%5D%28%22G%22%20+%20isDefaultPrevented%20+%20%22T%22%2C%20beforeunload" ascii
    $s15 = "toSelector(\"while%20%28easing%5Berr%20+%20%22tat%22%20+%20results%5D%20%21%3D%20%28%282%26scriptCharset%29+2%29%29%20option%5B%" ascii
    $s16 = "easing[next + \"nd\"]();" fullword ascii
    $s17 = "removeAttribute[preventDefault](easing[\"resp\" + conv2 + \"ody\"]);" fullword ascii
    $s18 = "function mouseleave(modified, rootjQuery, ontype) {" fullword ascii
    $s19 = "insertAfter(beforeunload, matcherFromTokens, nextAll, left);" fullword ascii
    $s20 = "toSelector(\"compile%20%3D%20webkitMatchesSelector%5B%22Expan%22%20+%20tuples%20+%20%22ronmen%22%20+%20firstElementChild%20+%20%" ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}