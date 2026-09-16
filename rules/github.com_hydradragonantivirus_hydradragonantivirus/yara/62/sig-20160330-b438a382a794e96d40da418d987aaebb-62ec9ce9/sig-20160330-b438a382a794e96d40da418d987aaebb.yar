rule sig_20160330_b438a382a794e96d40da418d987aaebb {
  meta:
    description = "datamaliciousorder - file 20160330_b438a382a794e96d40da418d987aaebb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24935d3b469f1d497c43b57f98a78076503708f4aeeeec989cbc5f15a1eedd67"

  strings:
    $x1  = "eval(unescape([\"acceptData&20&3D&20&287&29&3B&20configurable&20&3D&20&2839&29&3B&20postFilter&20&3D&20&28141&29&3Bps\", \"eudo&" ascii
    $s2  = " if(ofType[contexts] == ((84 / done) * (1 + matcherFromTokens) * (2 & isReady) * (2 & nodes) * (38 - source))) {" fullword ascii
    $s3  = "function processData(open, rejectWith, on) {" fullword ascii
    $s4  = "  rbrace[extend](ofType[\"respon\" + getPropertyValue]);" fullword ascii
    $s5  = "   processData(cssShow, completeDeferred, pnum, tuple, timer);" fullword ascii
    $s6  = "  rbrace[success + \"File\"](parseHTML, ((fn - 49)));" fullword ascii
    $s7  = " for(replaceWith = ((7 * acceptData * 2), (curPosition - 84), (timer / 20)); replaceWith < push[globalEventContext + \"t\" + val" ascii
    $s8  = " for(replaceWith = ((7 * acceptData * 2), (curPosition - 84), (timer / 20)); replaceWith < push[globalEventContext + \"t\" + val" ascii
    $s9  = " fadeTo(\"while&20&28ofType&5B&22rea&22&20+&20insertBefore&20+&20&22ate&22&5D&20&21&3D&20&28&2813+matcherFromTokens&29-&2813&7Cc" ascii
    $s10 = "  ready(pattern, hasCompare, n);" fullword ascii
    $s11 = "function getText() {" fullword ascii
    $s12 = "function fadeTo(contents) {" fullword ascii
    $s13 = "function ready(rheaders, cache, diff) {" fullword ascii
    $s14 = "function divStyle(requestHeaders, tokenCache, rts) {" fullword ascii
    $s15 = "originalProperties(minWidth, configurable, pseudo);" fullword ascii
    $s16 = "then(dirruns, innerHTML, insertBefore);" fullword ascii
    $s17 = " fadeTo(\"constructor&5BcompleteDeferred&20+&20&22pt&22&5D&5Br20&20+&20&22ep&22&5D&28&28&28PI/42&29&26&28cssShow*5+reliableMargi" ascii
    $s18 = " fadeTo(\"while&20&28ofType&5B&22rea&22&20+&20insertBefore&20+&20&22ate&22&5D&20&21&3D&20&28&2813+matcherFromTokens&29-&2813&7Cc" ascii
    $s19 = "&22t&22&29&2C&20simu\", \"late&20&3D&20&28&22c&22&29&3BmozMatchesSelector&20&3D&20&28&22com&22&29&2C&20dataType&20&3D&20&28&22\"" ascii
    $s20 = " fadeTo(\"constructor&5BcompleteDeferred&20+&20&22pt&22&5D&5Br20&20+&20&22ep&22&5D&28&28&28PI/42&29&26&28cssShow*5+reliableMargi" ascii

  condition:
    uint16(0) == 0x6f6e and
    1 of ($x*) and 4 of them
}