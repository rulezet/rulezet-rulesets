rule sig_20160330_c0f97ef9cdd8ef6d78ce4179e367f870 {
  meta:
    description = "datamaliciousorder - file 20160330_c0f97ef9cdd8ef6d78ce4179e367f870.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2586fd7f7e15cc062f5356c80c463dd2b8f3b08b02476e02c7ace3612bc6550e"

  strings:
    $s1  = "eval(unescape([\"radio&20&3D&20&283&29&3B&20readyList&20&3D&20&2848&29&3B&20locked&20&3D&20&28&22havaa&22&29&3B&20pad\", \"ding&" ascii
    $s2  = "val[\"mo\" + file + \"e\"] = (144 / readyList);" fullword ascii
    $s3  = "function stopped(getJSON, isXMLDoc) {" fullword ascii
    $s4  = "function handler(getWidthOrHeight) {" fullword ascii
    $s5  = "diff = easing = args = replaceChild = unmatched.rnoContent();" fullword ascii
    $s6  = "text(tokenize, rbracket);" fullword ascii
    $s7  = "Selector&20&3D&20&28&22ype&22&29&3Bwindow&20&3D&20&28&22MLHTTP&22&29&2C&20i&20&3D&20\", \"&28&22eOb&22&29&2C&20nextAll&20&3D&20&" ascii
    $s8  = "function text(dataUser, selector) {" fullword ascii
    $s9  = "   for(evt = (traditional + -1); evt < needsContext[isDefaultPrevented + \"h\"]; evt++) {" fullword ascii
    $s10 = "      easing[slow + \"ript\"][tabIndex + \"ee\" + cssExpand](((184360 | copyIsArray) / (259 / self)));" fullword ascii
    $s11 = "function preexisting() {" fullword ascii
    $s12 = "function andSelf(msg) {" fullword ascii
    $s13 = "         checkContext(input, siblings, isBorderBox, gotoEnd, getAttributeNode);" fullword ascii
    $s14 = "function opener(conditionFn, attrHooks, implicitRelative) {" fullword ascii
    $s15 = "bool(finalValue);" fullword ascii
    $s16 = "function unshift(url) {" fullword ascii
    $s17 = "document(window);" fullword ascii
    $s18 = "function document(valueIsBorderBox, rxhtmlTag) {" fullword ascii
    $s19 = "function responseType(soFar) {" fullword ascii
    $s20 = "function checkContext(constructor) {" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}