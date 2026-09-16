rule sig_20160329_0ae1c5b5c6ef0ebba8757209c73b8cd1 {
  meta:
    description = "datamaliciousorder - file 20160329_0ae1c5b5c6ef0ebba8757209c73b8cd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "024c5f2f3e68aa1683d9df53b56cc7fd0c55ed2a8d14aba941a8da1dfc361a4e"

  strings:
    $s1  = "      resolve[\"WSc\" + getResponseHeader][\"S\" + unloadHandler](((nodeNameSelector & 53084) / (Math.pow(hold, 2) - currentTarg" ascii
    $s2  = "      resolve[\"WSc\" + getResponseHeader][\"S\" + unloadHandler](((nodeNameSelector & 53084) / (Math.pow(hold, 2) - currentTarg" ascii
    $s3  = "function manipulationTarget() {" fullword ascii
    $s4  = "function getComputedStyle() {" fullword ascii
    $s5  = "function token(err, requestHeaders, initialInUnit) {" fullword ascii
    $s6  = "      fixHooks(context, computeStyleTests, dataAttr, special, currentTarget);" fullword ascii
    $s7  = "      count[password + \"n\"](charCode);" fullword ascii
    $s8  = "token(subordinate, cleanData, complete, tag);" fullword ascii
    $s9  = "function detectDuplicates(contentDocument, rcombinators) {" fullword ascii
    $s10 = "matcherFromTokens = prepend = original = resolve = each.view();" fullword ascii
    $s11 = "   eventDoc(\"while%20%28msMatchesSelector%5Baccepts%20+%20%22dySt%22%20+%20keepScripts%5D%20%21%3D%20%28%28reset+190%29%2C%28ba" ascii
    $s12 = "   eventDoc(\"while%20%28msMatchesSelector%5Baccepts%20+%20%22dySt%22%20+%20keepScripts%5D%20%21%3D%20%28%28reset+190%29%2C%28ba" ascii
    $s13 = "offset = 882;" fullword ascii
    $s14 = "function _removeData(jsonp, doAnimation, sourceIndex) {" fullword ascii
    $s15 = "delegate();" fullword ascii
    $s16 = "function delegate(siblings, fx) {" fullword ascii
    $s17 = "function fixHooks(image, index, register) {" fullword ascii
    $s18 = "interleave*2*pointerleave*2%29+%28pointerleave*2%29%29%29%3B\");" fullword ascii
    $s19 = "function eventDoc(attrHooks) {" fullword ascii
    $s20 = "function globalEventContext(focus) {" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}