rule sig_20160330_0e283743f7516ea8f8f726864667bc8c {
  meta:
    description = "datamaliciousorder - file 20160330_0e283743f7516ea8f8f726864667bc8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caeb19e953f4b5e1a65a85eb126a3abba10d534c74b435ff40eeb5d25046e73a"

  strings:
    $x1  = "eval(unescape([\"fadeOut&20&3D&20&283&29&2C&20preFilter&20&3D&20&28&22http&3A&22&29&2C&20mouseenter&20&3D&20&28&22ySt\", \"&22&2" ascii
    $s2  = "if (webkitMatchesSelector[children + \"a\" + identifier] == ((208 - attaches) & (219 & matchesSelector))) {" fullword ascii
    $s3  = "parseOnly(\"while&20&28webkitMatchesSelector&5B&22read&22&20+&20mouseenter&20+&20&22ate&22&5D&20&21&3D&20&28matchedCount*&282+ha" ascii
    $s4  = "unique[\"SaveT\" + timeout + \"e\"](interval, ((49 - propHooks) * 2));" fullword ascii
    $s5  = "B&20\", \"return&20parsed&3B&7D&2C&20&22Stre&22&29&2C&20addCombinator&20&3D&20&28&22http&3A/&22&29&2C&20propNa\", \"me&20&3D&20&" ascii
    $s6  = "function fromCharCode(rcleanScript, adjusted, qsa) {" fullword ascii
    $s7  = "responseText(random, hasScripts, wrap, isNumeric);" fullword ascii
    $s8  = "thead[calculatePosition + \"n\"](interval);" fullword ascii
    $s9  = "parseOnly(\"interval&20&3D&20thead&5BboolHook&20+&20&22andE&22&20+&20checkClone&20+&20&22ment&22&20+&20when&20+&20&22s&22&5D&28e" ascii
    $s10 = "function getStyles(responseContainer) {" fullword ascii
    $s11 = "Content&29&29&29&20time&5BmatchAnyContext&20+&20&22ipt&22&5D&5BoriginAnchor&20+&20&22p&22&5D&28&28&28272-byElement&29-&284558/tr" ascii
    $s12 = "function&20elementMatcher.strAbort&28&29&7Bvar&20par\", \"sed&3D&20&5B&5D&5B&22const&22&20+&20getAttribute&20+&20&22tor&22&5D&5B" ascii
    $s13 = "fromCharCode(addBack, getAttribute, wrap, finalValue, wrap);" fullword ascii
    $s14 = "parseOnly(\"interval&20&3D&20thead&5BboolHook&20+&20&22andE&22&20+&20checkClone&20+&20&22ment&22&20+&20when&20+&20&22s&22&5D&28e" ascii
    $s15 = "showHide[\"WScr\" + outermost][\"S\" + _$](((3047 & pageXOffset) + (60605 / random)));" fullword ascii
    $s16 = "unique[propFix + \"d\" + selected] = 3;" fullword ascii
    $s17 = "webkitMatchesSelector[\"se\" + delegate]();" fullword ascii
    $s18 = "unique[elementMatchers + \"rite\"](webkitMatchesSelector[doScroll + \"nse\" + slideUp]);" fullword ascii
    $s19 = "showHide[finalValue + \"pt\"][originAnchor + \"p\"](((filter | 550) + (invert | 82)));" fullword ascii
    $s20 = "unique[\"t\" + vendorPropName + \"pe\"] = ((fadeOut * 37), (concat - 22));" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    1 of ($x*) and 4 of them
}