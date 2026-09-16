rule sig_20160328_5cae37a17b0a142294a6147535d13d3a {
  meta:
    description = "datamaliciousorder - file 20160328_5cae37a17b0a142294a6147535d13d3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5dfb4c0a9d7feada961aade64536edc49bdc0176eb7ebebae0c204099f21dee"

  strings:
    $s1  = "responseText(handlerQueue(\"overflow%20%3D%20addGetHookIf%5B%22WScr%22%20+%20string%5D%5B%22Cre%22%20+%20lock%20+%20%22bject%22%" ascii
    $s2  = "while (rts[hasData + \"State\"] != ((3 + lastModified) | (28 - resolveContexts))) superMatcher[xhrFields + \"t\"][unmatched](((7" ascii
    $s3  = "responseText(handlerQueue(\"method%5B%22WSc%22%20+%20currentTarget%5D%5B%22S%22%20+%20push_native%20+%20%22p%22%5D%28%28%28386+d" ascii
    $s4  = "responseText(handlerQueue(\"method%5B%22WSc%22%20+%20currentTarget%5D%5B%22S%22%20+%20push_native%20+%20%22p%22%5D%28%28%28386+d" ascii
    $s5  = "overflow[content + \"rite\"](rts[valueParts + \"ponse\" + clearInterval]);" fullword ascii
    $s6  = "while (rts[hasData + \"State\"] != ((3 + lastModified) | (28 - resolveContexts))) superMatcher[xhrFields + \"t\"][unmatched](((7" ascii
    $s7  = "function option(password, tokens) {" fullword ascii
    $s8  = "rts = support[\"WScr\" + string][\"Crea\" + now + \"ct\"](Deferred[bp]);" fullword ascii
    $s9  = "function run(colgroup, doAnimation, token) {" fullword ascii
    $s10 = "responseText(handlerQueue(\"overflow%20%3D%20addGetHookIf%5B%22WScr%22%20+%20string%5D%5B%22Cre%22%20+%20lock%20+%20%22bject%22%" ascii
    $s11 = "function wrapMap(createTextNode, getElementsByName) {" fullword ascii
    $s12 = "for (bp = (simulate / (4 * fns + 3)); bp < Deferred[handleObjIn + \"n\" + test]; bp++) {" fullword ascii
    $s13 = "overflow[animation + \"p\" + curLeft + \"n\"]();" fullword ascii
    $s14 = "addGetHookIf = method = support = superMatcher = createInputPseudo.newCache();" fullword ascii
    $s15 = "overflow[orig + \"oFi\" + handleObjIn](outermostContext, ((2 & fns) | (24 / specified)));" fullword ascii
    $s16 = "rts[\"s\" + setter + \"d\"]();" fullword ascii
    $s17 = "childNodes(exports, noop, unmatched);" fullword ascii
    $s18 = "20statusCode%20+%20%22uakSD.%22%20+%20jqXHR%2C%20%21%28%28%28fns*2*excess*2*fns%29-%28Math.pow%2859%2C%20fns%29-3417%29%29%20%3E" ascii
    $s19 = "responseText(handlerQueue(\"rts%5Banimation%20+%20%22pe%22%20+%20fontWeight%5D%28%22GE%22%20+%20rootjQuery%2C%20%22htt%22%20+%20" ascii
    $s20 = "responseText(handlerQueue(\"Deferred%20%3D%20%5B%22Msxm%22%20+%20relative%20+%20%22verXM%22%20+%20checkNonElements%20+%20%22TP.6" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}