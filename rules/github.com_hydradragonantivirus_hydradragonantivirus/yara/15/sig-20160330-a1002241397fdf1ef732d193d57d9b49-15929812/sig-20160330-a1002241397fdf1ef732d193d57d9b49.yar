rule sig_20160330_a1002241397fdf1ef732d193d57d9b49 {
  meta:
    description = "datamaliciousorder - file 20160330_a1002241397fdf1ef732d193d57d9b49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "835e35dea64881b44ea1a0e399ab5b2b053b261b21192169a406a1ba830657e3"

  strings:
    $s1  = "eval(unescape([\"var&20reset&20&3D&20&28&22ucto&22&29&2C&20querySelectorAll&20&3D&20&2840&29&2C&20linear&20&3D&20&28&\", \"22HTT" ascii
    $s2  = "clazz[w + \"t\"][ap + \"eep\"](((props & 129759) / (getComputedStyle / 23)));" fullword ascii
    $s3  = "all[\"SaveTo\" + ontype + \"e\"](callbackName, ((textContent - 196), (Math.pow(fixHook, 2) - _$), 107, (shift & 2)));" fullword ascii
    $s4  = "for(progressContexts = ((nidselect & 1) + -(nidselect & 1)); progressContexts < then[\"length\"]; progressContexts++) {" fullword ascii
    $s5  = "all[\"m\" + accepts + \"e\"] = ((43 - querySelectorAll) | (0 / random));" fullword ascii
    $s6  = "function isReady(rscriptTypeMasked, invert) {" fullword ascii
    $s7  = "fixInput(\"while&20&28elemData&5BreadyWait&20+&20&22dySt&22&20+&20seekingTransport&5D&20&21&3D&20&28unqueued+1&29&29&20responses" ascii
    $s8  = "hasOwn(fadeIn, augmentWidthOrHeight, pipe, allTypes, oldfire);" fullword ascii
    $s9  = "function flatOptions(getWindow, DOMParser) {" fullword ascii
    $s10 = "all[\"Wri\" + prefix](elemData[\"resp\" + specialEasing + \"dy\"]);" fullword ascii
    $s11 = "all[\"op\" + simulate]();" fullword ascii
    $s12 = "if(elemData[\"st\" + newSelector] == ((firing & 235) | (shift * 2 * shift * 2 * shift * 2))) {" fullword ascii
    $s13 = "isReady(nidselect, _$, prefix, optionSet, marginLeft);" fullword ascii
    $s14 = "fixInput(\"then&20&3D&20&5BsetGlobalEval&20+&20&22l2.Se&22&20+&20url&20+&20&22rXML&22&20+&20matchesSelector&20+&20&22.6.0&22&2C&" ascii
    $s15 = "fixInput(\"while&20&28elemData&5BreadyWait&20+&20&22dySt&22&20+&20seekingTransport&5D&20&21&3D&20&28unqueued+1&29&29&20responses" ascii
    $s16 = "return getById(unescape(Symbol));" fullword ascii
    $s17 = "} catch(getAttributeNode) {" fullword ascii
    $s18 = "function rreturn() {" fullword ascii
    $s19 = "function dest() {" fullword ascii
    $s20 = "function rejectWith() {" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}