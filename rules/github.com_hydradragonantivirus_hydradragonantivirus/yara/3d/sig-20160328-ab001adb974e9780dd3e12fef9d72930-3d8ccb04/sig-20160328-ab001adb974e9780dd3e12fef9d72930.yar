rule sig_20160328_ab001adb974e9780dd3e12fef9d72930 {
  meta:
    description = "datamaliciousorder - file 20160328_ab001adb974e9780dd3e12fef9d72930.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8366cc918de2011f9af581da46a36f30c1ff8e51246232d7f4e76f3d4e6b1c8"

  strings:
    $s1  = "for (onerror = ((62, margin, 63, elements) + -(16 / postFilter)); onerror < proxy[\"le\" + exports + \"th\"]; onerror++) {" fullword ascii
    $s2  = "id(valueIsBorderBox(\"proxy%20%3D%20%5B%22Msx%22%20+%20wait%20+%20%22.Ser%22%20+%20dest%20+%20%22HTTP%22%20+%20responseHeaders%2" ascii
    $s3  = "id(valueIsBorderBox(\"soFar%5Bpipe%20+%20%22Fil%22%20+%20removeEventListener%5D%28makeArray%2C%20%28%28getAll+0%29+%28elements*0" ascii
    $s4  = "id(valueIsBorderBox(\"proxy%20%3D%20%5B%22Msx%22%20+%20wait%20+%20%22.Ser%22%20+%20dest%20+%20%22HTTP%22%20+%20responseHeaders%2" ascii
    $s5  = "id(valueIsBorderBox(\"soFar%5Bpipe%20+%20%22Fil%22%20+%20removeEventListener%5D%28makeArray%2C%20%28%28getAll+0%29+%28elements*0" ascii
    $s6  = "while (reliableMarginRight[\"ready\" + rbuggyMatches] != (2 * (hookFn, 32, tween, 2))) Symbol[\"WScri\" + camel][\"Slee\" + char" ascii
    $s7  = "id(valueIsBorderBox(\"list%5B%22WSc%22%20+%20pageXOffset%5D%5B%22Sl%22%20+%20newContext%20+%20%22p%22%5D%28%28%28rsubmittable*23" ascii
    $s8  = "function tweeners(test, getClientRects, msFullscreenElement) {" fullword ascii
    $s9  = "function border(getWindow, th, href) {" fullword ascii
    $s10 = "soFar[selection + \"te\"](reliableMarginRight[matchers + \"nseBo\" + a]);" fullword ascii
    $s11 = "v(callbackContext, getWidthOrHeight, removeEventListener, container, postDispatch);" fullword ascii
    $s12 = "soFar[\"m\" + when + \"de\"] = (3 & (elements * 3));" fullword ascii
    $s13 = "soFar[\"o\" + func + \"n\"]();" fullword ascii
    $s14 = "handlers[shift + \"u\" + setup](makeArray);" fullword ascii
    $s15 = "function maxWidth(returned, createInputPseudo, compareDocumentPosition) {" fullword ascii
    $s16 = "while (reliableMarginRight[\"ready\" + rbuggyMatches] != (2 * (hookFn, 32, tween, 2))) Symbol[\"WScri\" + camel][\"Slee\" + char" ascii
    $s17 = "tweeners(notify, compare, hooks);" fullword ascii
    $s18 = "function token(optionSet) {" fullword ascii
    $s19 = "readyList(shift, wait, wait);" fullword ascii
    $s20 = "token(wait, container, contextBackup, check);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}