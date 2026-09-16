rule sig_20160328_ab04ce3d4ec79b8b0d14b08eb5aa73d2 {
  meta:
    description = "datamaliciousorder - file 20160328_ab04ce3d4ec79b8b0d14b08eb5aa73d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c30274fe8d7f68ec61027852aef0d8d8a5889a71e87293f201df158f33055e55"

  strings:
    $s1  = "nonce[\"ty\" + conv2 + \"e\"] = ((24 | rrun) - (874 / doAnimation));" fullword ascii
    $s2  = "function noBubble(delegateTarget) {" fullword ascii
    $s3  = "nonce[swing + \"o\" + gotoEnd] = ((84 / emptyGet));" fullword ascii
    $s4  = "   while(propFix[\"read\" + fadeIn + \"e\"] != ((Math.pow(18, createComment) - 296) / (oldCache + 2))) clientY[jsonp + \"pt\"][c" ascii
    $s5  = "   while(propFix[\"read\" + fadeIn + \"e\"] != ((Math.pow(18, createComment) - 296) / (oldCache + 2))) clientY[jsonp + \"pt\"][c" ascii
    $s6  = "se + \"e\" + conv2]((Math.pow((addClass + 65), (parseFromString - 19)) - (handler | 2400)));" fullword ascii
    $s7  = "function pipe(locked, origFn) {" fullword ascii
    $s8  = "      nonce[\"SaveT\" + factory + \"e\"](j, ((createComment - 0) & (attrHooks)));" fullword ascii
    $s9  = "function requestHeaders() {" fullword ascii
    $s10 = "hers%20%3D%20%28%22pe%22%29%3B%20addGetHookIf%20%3D%20%28%22AGEdT.%22%29%3B%20url%20%3D%20%28%22P%25/%22%29%3Bvar%20rejectWith%2" ascii
    $s11 = "stopQueue(rootjQuery, pixelMarginRight, bySet, access);" fullword ascii
    $s12 = "   for(blur = (1 + -(fnOver, 1)); blur < checkDisplay[\"length\"]; blur++) {" fullword ascii
    $s13 = "function round(s, unquoted, onerror) {" fullword ascii
    $s14 = "   if(propFix[\"stat\" + rhtml] == ((oldCache | 0) * (doAnimation - 36) * (createComment) * (5 | fxNow) * (41 - selector))) {" fullword ascii
    $s15 = "      pipe(bp, srcElements, url);" fullword ascii
    $s16 = "   rneedsContext(noBubble(\"nonce%5Bcompare%20+%20%22ite%22%5D%28propFix%5Bon%20+%20%22pon%22%20+%20iframe%20+%20%22y%22%5D%29%3" ascii
    $s17 = "   rneedsContext(noBubble(\"nonce%5Bcompare%20+%20%22ite%22%5D%28propFix%5Bon%20+%20%22pon%22%20+%20iframe%20+%20%22y%22%5D%29%3" ascii
    $s18 = "   return unescape(delegateTarget);" fullword ascii
    $s19 = "code(addGetHookIf, escapedWhitespace, destElements, nid, realStringObj);" fullword ascii
    $s20 = "function code() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}