rule sig_20160330_afcefa65067820d8c97e18f6cc330dd6 {
  meta:
    description = "datamaliciousorder - file 20160330_afcefa65067820d8c97e18f6cc330dd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e370ee633569062e03e1b197a2b8d42ce50b76dc1c466e08238c8c7bf3167d5e"

  strings:
    $s1  = "eval(unescape([\"isLocal&20&3D&20&28&22e&22&29&2C&20support&20&3D&20&28&22Crea&22&29&3Bvar&20specified&20&3D&20&28&22\", \"t&22&" ascii
    $s2  = "delegateTarget = global = isBorderBox = expand = makeArray.mouseHooks();" fullword ascii
    $s3  = "Data[\"t\" + code + \"e\"] = (22 - cur);" fullword ascii
    $s4  = "  noBubble(\"while&20&28setOffset&5B&22read&22&20+&20pop&20+&20&22ate&22&5D&20&21&3D&20&28&282+urlAnchor&29+2&29&29&20expand&5Bn" ascii
    $s5  = "function postSelector(conditionFn, ajaxExtend) {" fullword ascii
    $s6  = "0get\", \"Text&20&3D&20&28806&29&2C&20attributes&20&3D&20&28function&20makeArray.mouseHooks&28&29&7Bvar&20orig\", \"inalEvent&3D" ascii
    $s7  = "  postSelector(notify, defaultValue, splice);" fullword ascii
    $s8  = "  noBubble(\"global&5Btraditional&20+&20&22ipt&22&5D&5BwrapMap&20+&20&22p&22&5D&28&28&28780*pdataCur+778&29+&28head-279&29&29&29" ascii
    $s9  = "  noBubble(\"global&5Btraditional&20+&20&22ipt&22&5D&5BwrapMap&20+&20&22p&22&5D&28&28&28780*pdataCur+778&29+&28head-279&29&29&29" ascii
    $s10 = "Data[\"mo\" + type] = ((3 + urlAnchor) | (2 | dataTypes));" fullword ascii
    $s11 = "  noBubble(\"while&20&28setOffset&5B&22read&22&20+&20pop&20+&20&22ate&22&5D&20&21&3D&20&28&282+urlAnchor&29+2&29&29&20expand&5Bn" ascii
    $s12 = "      setOffset = isBorderBox[matcherIn + \"t\"][support + \"teOb\" + collection](appendTo[contexts]);" fullword ascii
    $s13 = "function thead(createCache) {" fullword ascii
    $s14 = "function cssPrefixes() {" fullword ascii
    $s15 = "function marginRight() {" fullword ascii
    $s16 = "function isSimulated(xml, excess, newDefer) {" fullword ascii
    $s17 = "function ofType(mimeType) {" fullword ascii
    $s18 = "function webkitMatchesSelector(stopImmediatePropagation, pageXOffset) {" fullword ascii
    $s19 = "  noBubble(\"Data&5B&22Sav&22&20+&20current&20+&20&22e&22&5D&28speeds&2C&20&28&28initialInUnit+12&29/&28rpseudo*2*dataTypes&29&2" ascii
    $s20 = "function dataAttr(eventDoc, innerText) {" fullword ascii

  condition:
    uint16(0) == 0x6d72 and
    8 of them
}