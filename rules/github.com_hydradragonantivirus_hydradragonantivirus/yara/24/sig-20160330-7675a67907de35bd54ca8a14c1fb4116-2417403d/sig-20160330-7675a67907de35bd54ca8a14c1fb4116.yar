rule sig_20160330_7675a67907de35bd54ca8a14c1fb4116 {
  meta:
    description = "datamaliciousorder - file 20160330_7675a67907de35bd54ca8a14c1fb4116.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b71805ae50826f101b0850735d2ba36d2498ba5ee268bc7e407c2669a8cea4c8"

  strings:
    $x1  = "eval(unescape([\"attributes&20&3D&20&28&22rip&22&29&3B&20isReady&20&3D&20&28&22c&22&29&3B&20mozMatchesSelector&20&3D&\", \"20&28" ascii
    $s2  = "$[protocol](thead[\"res\" + temp + \"Body\"]);" fullword ascii
    $s3  = "$[processData + \"d\" + prop] = (3 & implementation);" fullword ascii
    $s4  = "if (thead[\"stat\" + detectDuplicates] == ((3 & getter) * (54 - insertBefore) * 2 * (Math.pow(els, 2) - params) * 2)) {" fullword ascii
    $s5  = "$[\"SaveT\" + urlAnchor + \"le\"](originalEvent, ((getter | 0) + (p / 47)));" fullword ascii
    $s6  = "function markFunction(rkeyEvent) {" fullword ascii
    $s7  = "function getById(rbuggyQSA, identifier, fire) {" fullword ascii
    $s8  = "parsed(\"while&20&28thead&5Bsibling&20+&20&22dyS&22&20+&20compile&5D&20&21&3D&20&28&28fcamelCase&7C10&29-&28Math.pow&28els&2C&20" ascii
    $s9  = "$[\"t\" + excess + \"pe\"] = ((184, readyList, 150, defer) & 1);" fullword ascii
    $s10 = "parsed(\"while&20&28thead&5Bsibling&20+&20&22dyS&22&20+&20compile&5D&20&21&3D&20&28&28fcamelCase&7C10&29-&28Math.pow&28els&2C&20" ascii
    $s11 = "function requestHeaders() {" fullword ascii
    $s12 = "Data = cssPrefixes = origFn = outermostContext = contextBackup.postFilter();" fullword ascii
    $s13 = "winnow(urlAnchor, needsContext, getter, defaultView, beforeSend);" fullword ascii
    $s14 = "height(wait, delegateType, compile);" fullword ascii
    $s15 = "f&20+&20&22l&22&20+&20excess&5D&28&29&3B&20return&20matchCon\", \"text&3B&7D&2C&20&22soft.X&22&29&2C&20rootjQuery&20&3D&20&28&22" ascii
    $s16 = "useCache(animate, propHooks, getElementById, origName);" fullword ascii
    $s17 = "function testContext() {" fullword ascii
    $s18 = "function winnow() {" fullword ascii
    $s19 = "function rbrace() {" fullword ascii
    $s20 = "ordinate&20+&20&22ml2.XM&22&20+&20globalEval&20+&20&22TP.3.0&22&2C&20view&20+&20&22l2.XM&22&20+&20elementMatchers&2C&20&22Micro&" ascii

  condition:
    uint16(0) == 0x6474 and
    1 of ($x*) and 4 of them
}