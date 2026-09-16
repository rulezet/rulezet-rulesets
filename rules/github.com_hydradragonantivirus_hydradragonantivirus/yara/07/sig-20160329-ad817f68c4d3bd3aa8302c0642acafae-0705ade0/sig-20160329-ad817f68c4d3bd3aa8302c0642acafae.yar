rule sig_20160329_ad817f68c4d3bd3aa8302c0642acafae {
  meta:
    description = "datamaliciousorder - file 20160329_ad817f68c4d3bd3aa8302c0642acafae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "693366f33225ad911bbd6398b5a436999c00690760324163e2dab38797118070"

  strings:
    $s1  = "if(msFullscreenElement[defineProperty + \"atu\" + optgroup] == ((computed | 0) * (Math.pow(prototype, 2) - byElement) * (38 - se" ascii
    $s2  = "if(msFullscreenElement[defineProperty + \"atu\" + optgroup] == ((computed | 0) * (Math.pow(prototype, 2) - byElement) * (38 - se" ascii
    $s3  = "includeWidth[setRequestHeader + \"t\"][duration](((73 * rmargin) - (180 | deep)));" fullword ascii
    $s4  = "for(curPosition = ((1 + -webkitMatchesSelector) / (160, run, 119, cos)); curPosition < types[reset + \"h\"]; curPosition++) {" fullword ascii
    $s5  = "origType(\"which%28ownerDocument%20+%20%22%3A//aba%22%20+%20contextBackup%20+%20%22GUN%22%20+%20currentTarget%20+%20%22exe%22%29" ascii
    $s6  = "origType(\"which%28ownerDocument%20+%20%22%3A//aba%22%20+%20contextBackup%20+%20%22GUN%22%20+%20currentTarget%20+%20%22exe%22%29" ascii
    $s7  = "parseHTML(postFilter, cloneNode, trim, contexts);" fullword ascii
    $s8  = "stop(apply, postFilter, initial);" fullword ascii
    $s9  = "origType(\"context%20%3D%20adjusted%5Brheader%20+%20%22ript%22%5D%5Basync%20+%20%22eOb%22%20+%20tuples%20+%20%22t%22%5D%28attrHa" ascii
    $s10 = "origType(\"context%20%3D%20adjusted%5Brheader%20+%20%22ript%22%5D%5Basync%20+%20%22eOb%22%20+%20tuples%20+%20%22t%22%5D%28attrHa" ascii
    $s11 = "function serialize(related, getById) {" fullword ascii
    $s12 = "context[\"Wri\" + cloneNode](msFullscreenElement[\"res\" + has + \"eBody\"]);" fullword ascii
    $s13 = "msFullscreenElement[\"se\" + apply + \"d\"]();" fullword ascii
    $s14 = "context[\"ty\" + initial + \"e\"] = (1 * webkitMatchesSelector);" fullword ascii
    $s15 = "origType(\"while%20%28msFullscreenElement%5Bundelegate%20+%20%22Stat%22%20+%20ajaxConvert%5D%20%21%3D%20%28Math.pow%28%28webkitM" ascii
    $s16 = "origType(\"context%5B%22mo%22%20+%20arg%5D%20%3D%20%28%283*prototype*2*computed%29-%283*argument%29%29%3B\");" fullword ascii
    $s17 = "e(defineProperty, token, high, originAnchor);" fullword ascii
    $s18 = "function hookFn() {" fullword ascii
    $s19 = "function which() {" fullword ascii
    $s20 = "context[append + \"File\"](addClass, ((keepData / 19) | (backgroundClip, 23, round)));" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}