rule sig_20160329_6f312c2d3c36e9ca7f0281a95883cda7 {
  meta:
    description = "datamaliciousorder - file 20160329_6f312c2d3c36e9ca7f0281a95883cda7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fb4a651783004383474973d48494bf1cd2933893f2052a8191b04cec2250a3e"

  strings:
    $s1  = "  preFilters[\"WSc\" + unit][\"S\" + responseHeaders + \"ep\"]((Math.pow((getAttributeNode - 917), (isReady)) - (470918616 / def" ascii
    $s2  = "  preFilters[\"WSc\" + unit][\"S\" + responseHeaders + \"ep\"]((Math.pow((getAttributeNode - 917), (isReady)) - (470918616 / def" ascii
    $s3  = " whitespace(\"while%20%28isPropagationStopped%5B%22read%22%20+%20bind%5D%20%21%3D%20%28%28getPropertyValue*4%29%7C%28eq%2C0%29%2" ascii
    $s4  = " whitespace(\"while%20%28isPropagationStopped%5B%22read%22%20+%20bind%5D%20%21%3D%20%28%28getPropertyValue*4%29%7C%28eq%2C0%29%2" ascii
    $s5  = " whitespace(\"constructor%28outermostContext%20+%20%22%3A//%22%20+%20old%20+%20%22rpart%22%20+%20sortDetached%20+%20%22.com/A%22" ascii
    $s6  = " whitespace(\"constructor%28outermostContext%20+%20%22%3A//%22%20+%20old%20+%20%22rpart%22%20+%20sortDetached%20+%20%22.com/A%22" ascii
    $s7  = "  tokenCache[uid + \"ToF\" + selection](keepScripts, (2));" fullword ascii
    $s8  = " whitespace(\"scale%20%3D%20%5BstopOnFalse%20+%20%22l2.Se%22%20+%20postDispatch%20+%20%22XMLH%22%20+%20removeClass%20+%20%226.0%" ascii
    $s9  = "  notify(doc, isReady, bind, bind);" fullword ascii
    $s10 = "docElem(getAttributeNode, vendorPropName, v, document);" fullword ascii
    $s11 = "function holdReady(left, pixelPosition) {" fullword ascii
    $s12 = "  tokenCache[\"Wr\" + rnamespace](isPropagationStopped[\"res\" + next + \"seBody\"]);" fullword ascii
    $s13 = " whitespace(\"scale%20%3D%20%5BstopOnFalse%20+%20%22l2.Se%22%20+%20postDispatch%20+%20%22XMLH%22%20+%20removeClass%20+%20%226.0%" ascii
    $s14 = "classCache(getJSON, responseHeaders, postFilter, show, stored);" fullword ascii
    $s15 = "function constructor() {" fullword ascii
    $s16 = "function stopped() {" fullword ascii
    $s17 = "function implementation() {" fullword ascii
    $s18 = "function notify(dataAndEvents, rsubmitterTypes, isArray) {" fullword ascii
    $s19 = "implementation(sortDetached, defineProperty, sortOrder);" fullword ascii
    $s20 = " for (parents = ((conv2 / 32) & conv2); parents < scale[multipleContexts + \"h\"]; parents++) {" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}