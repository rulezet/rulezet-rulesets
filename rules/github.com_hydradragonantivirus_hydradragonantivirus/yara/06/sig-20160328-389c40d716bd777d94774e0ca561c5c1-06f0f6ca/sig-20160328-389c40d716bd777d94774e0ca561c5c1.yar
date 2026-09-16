rule sig_20160328_389c40d716bd777d94774e0ca561c5c1 {
  meta:
    description = "datamaliciousorder - file 20160328_389c40d716bd777d94774e0ca561c5c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83b40b7cb3ad41c1a7999701c50aebda6da355e98bdcfb839a45c3d990d556ba"

  strings:
    $x1  = "eval(result(\"var%20writable%20%3D%20%28%22%25/%22%29%3Bvar%20fadeToggle%20%3D%20%28%22or%22%29%2C%20deep%20%3D%20%28%22nmen%22%" ascii
    $s2  = "augmentWidthOrHeight(result(\"tmp%20%3D%20%5B%22Msxm%22%20+%20rinputs%20+%20%22erver%22%20+%20disconnectedMatch%20+%20%22HTTP.6%" ascii
    $s3  = "while(completeDeferred[\"readyS\" + transport + \"e\"] != ((2 * actualDisplay) - (5 * classes * 3))) ret[nidselect + \"rip\" + u" ascii
    $s4  = "augmentWidthOrHeight(result(\"completeDeferred%5Bradio%20+%20%22pe%22%20+%20destElements%5D%28%22G%22%20+%20runescape%2C%20%22ht" ascii
    $s5  = "while(completeDeferred[\"readyS\" + transport + \"e\"] != ((2 * actualDisplay) - (5 * classes * 3))) ret[nidselect + \"rip\" + u" ascii
    $s6  = "completeDeferred = mapped[nidselect + \"ript\"][getElementsByName + \"Object\"](tmp[original]);" fullword ascii
    $s7  = "for(original = (1 + -rcombinators); original < tmp[dir + \"th\"]; original++) {" fullword ascii
    $s8  = "newUnmatched[origCount + \"ipt\"][matcherFromTokens + \"eep\"](((iterator / 36) - (size - 1395)));" fullword ascii
    $s9  = "condense(unique, getWidthOrHeight, binary, raw, username);" fullword ascii
    $s10 = "delegate[\"ty\" + proxy] = (1 * rcombinators);" fullword ascii
    $s11 = "augmentWidthOrHeight(result(\"div1%28%22http%3A%22%20+%20adown%20+%20%22oci%22%20+%20attr%20+%20%22in/Hw%22%20+%20attrHooks%20+%" ascii
    $s12 = "andler][\"Sl\" + script](((classes) * (110 / raw) * (70 / username) * (5 & status)));" fullword ascii
    $s13 = "function rdisplayswap(isXMLDoc, remaining, password) {" fullword ascii
    $s14 = "domManip[elemLang + \"n\"](unbind);" fullword ascii
    $s15 = "augmentWidthOrHeight(result(\"unbind%20%3D%20domManip%5B%22Expan%22%20+%20compareDocumentPosition%20+%20%22viro%22%20+%20deep%20" ascii
    $s16 = "delegate[\"o\" + proxy + \"n\"]();" fullword ascii
    $s17 = "function disableScript() {" fullword ascii
    $s18 = "augmentWidthOrHeight(result(\"tmp%20%3D%20%5B%22Msxm%22%20+%20rinputs%20+%20%22erver%22%20+%20disconnectedMatch%20+%20%22HTTP.6%" ascii
    $s19 = "augmentWidthOrHeight(result(\"domManip%20%3D%20hide%5B%22WSc%22%20+%20rfxtypes%5D%5B%22Create%22%20+%20ignored%20+%20%22t%22%5D%" ascii
    $s20 = "delegate[dispatch + \"File\"](unbind, ((3 | classes) & 2));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}