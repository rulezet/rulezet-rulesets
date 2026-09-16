rule sig_20160328_899963970cce7921f97fbe5d3e0acf47 {
  meta:
    description = "datamaliciousorder - file 20160328_899963970cce7921f97fbe5d3e0acf47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffe214782fca0d694236bb774e5b876c8d22891a813ddd9d94c3bec557fd1dab"

  strings:
    $s1  = "while(curCSS[\"read\" + returnTrue + \"ate\"] != (radio * (4 + dirrunsUnique))) rheader[tokens + \"t\"][inspected + \"ep\"](((12" ascii
    $s2  = "while(curCSS[\"read\" + returnTrue + \"ate\"] != (radio * (4 + dirrunsUnique))) rheader[tokens + \"t\"][inspected + \"ep\"](((12" ascii
    $s3  = "tweens[values + \"pt\"][currentTarget](((3548 + round) | (272 + l)));" fullword ascii
    $s4  = "scriptCharset[\"m\" + seed + \"d\" + push_native] = ((74 - visibility) - (Math.pow(7, classCache) - 39));" fullword ascii
    $s5  = "module(visibility, removeAttr, tokens, disableScript, fixHook);" fullword ascii
    $s6  = "for(elements = ((32 + response) - (1034 / setter)); elements < dequeue[\"len\" + matchContext]; elements++) {" fullword ascii
    $s7  = "function emptyGet(booleans, complete) {" fullword ascii
    $s8  = "if(curCSS[isArray] == ((Math.pow(362, classCache) - 130629) - (createButtonPseudo, 179, speed))) {" fullword ascii
    $s9  = "emptyGet(returnTrue, disable, rmultiDash, text, tfoot);" fullword ascii
    $s10 = "curCSS[propFix + \"e\" + setup]();" fullword ascii
    $s11 = "Offset%20%3D%20%28%22pt%22%29%3Bvar%20opts%20%3D%20%28%22P.3.%22%29%3BcompareDocumentPosition%20%3D%20%28%22TTP.%22%29%2C%20posi" ascii
    $s12 = "selected();" fullword ascii
    $s13 = "status();" fullword ascii
    $s14 = "memory();" fullword ascii
    $s15 = "function defaultView() {" fullword ascii
    $s16 = "function selected(_queueHooks, dataFilter, initialInUnit) {" fullword ascii
    $s17 = "defaultView(opacity, overflow);" fullword ascii
    $s18 = "function cssNormalTransform(nativeStatusText) {" fullword ascii
    $s19 = "function memory(cssShow) {" fullword ascii
    $s20 = "function module(udataOld, replaceWith) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}