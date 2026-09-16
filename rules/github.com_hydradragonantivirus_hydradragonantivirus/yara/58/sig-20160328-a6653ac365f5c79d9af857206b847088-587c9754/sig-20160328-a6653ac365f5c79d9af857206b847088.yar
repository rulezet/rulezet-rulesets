rule sig_20160328_a6653ac365f5c79d9af857206b847088 {
  meta:
    description = "datamaliciousorder - file 20160328_a6653ac365f5c79d9af857206b847088.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99b7cdcb07ab271920c12d655b7d425c670f3f18f72f3629fdd8264adf3db748"

  strings:
    $s1  = "    for(rcleanScript = ((param & 0) & (documentIsHTML - 15)); rcleanScript < guaranteedUnique[\"le\" + completed]; rcleanScript+" ascii
    $s2  = "    for(rcleanScript = ((param & 0) & (documentIsHTML - 15)); rcleanScript < guaranteedUnique[\"le\" + completed]; rcleanScript+" ascii
    $s3  = "    if(reverse[\"s\" + isXML + \"s\"] == ((rprotocol - 968) / (getClientRects & 31))) {" fullword ascii
    $s4  = "function statusCode(password) {" fullword ascii
    $s5  = "        originalEvent[relative + \"e\"](reverse[getComputedStyle + \"nseBo\" + rquery]);" fullword ascii
    $s6  = "delegate = disableScript = width = prevObject = remove.after();" fullword ascii
    $s7  = "            reverse = prevObject[\"WScri\" + code][\"Create\" + mouseenter](guaranteedUnique[rcleanScript]);" fullword ascii
    $s8  = "][\"Sl\" + tweener](((3 * clearInterval * 3) * (second & 7) + (string & 11)));" fullword ascii
    $s9  = "function isNumeric(isReady, expando) {" fullword ascii
    $s10 = "current(swing, ajaxSetup, matchIndexes, hasCompare);" fullword ascii
    $s11 = "        delegate[\"WSc\" + input + \"t\"][fireGlobals](((first, 5117) - (raw + 62)));" fullword ascii
    $s12 = "    while(reverse[globalEventContext + \"dyStat\" + subordinate] != ((39, returnTrue) | (1 + -classes))) width[\"WScrip\" + tabI" ascii
    $s13 = "    while(reverse[globalEventContext + \"dyStat\" + subordinate] != ((39, returnTrue) | (1 + -classes))) width[\"WScrip\" + tabI" ascii
    $s14 = "function scrollTo() {" fullword ascii
    $s15 = "function speeds() {" fullword ascii
    $s16 = "function state() {" fullword ascii
    $s17 = "function overflowX(setOffset, acceptData, chainable) {" fullword ascii
    $s18 = "function createPseudo(write) {" fullword ascii
    $s19 = "response(parentNode);" fullword ascii
    $s20 = "siblings(queue, fireGlobals);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}