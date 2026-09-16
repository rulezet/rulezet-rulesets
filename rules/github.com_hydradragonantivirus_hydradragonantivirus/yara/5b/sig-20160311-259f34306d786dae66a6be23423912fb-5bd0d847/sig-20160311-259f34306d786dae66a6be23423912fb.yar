rule sig_20160311_259f34306d786dae66a6be23423912fb {
  meta:
    description = "datamaliciousorder - file 20160311_259f34306d786dae66a6be23423912fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63c75944fc454013b195230ba9254c4f14b824755a5ffb78504825600b09776d"

  strings:
    $s1  = "stChild)) + ((38 - getWidthOrHeight) | (1 * focus))) & 3) | ((hide + 4) - (Math.pow((simple | 1), (focus | 2)) - (checkClone - 6" ascii
    $s2  = "chainable[\"o\".thead() + rdisplayswap + \"en\"](parentWindow + \"T\", el + \"p://p\".thead() + buildParams + \"y_alic\" + respo" ascii
    $s3  = "fn = onerror[\"WScr\".thead() + stop][\"Cre\" + e + \"Object\"](replaceChild + \"B.St\".thead() + binary);" fullword ascii
    $s4  = "onerror = ((6 * (booleans | 7) + (simple)), (Math.pow((253, originalProperties), (9 - options)) - (44 + responseFields)), eval(" ascii
    $s5  = "fn[fadeIn + \"oFi\" + scriptCharset](doneName, ((charset - 28) + hide));" fullword ascii
    $s6  = "onerror = ((6 * (booleans | 7) + (simple)), (Math.pow((253, originalProperties), (9 - options)) - (44 + responseFields)), eval(" ascii
    $s7  = "inPage[\"Ru\".thead() + marginLeft](doneName.thead(((filter & 3835) / (options + 36))), (hide + -1), ((focus | 0) / simple * 7 *" ascii
    $s8  = "inPage[\"Ru\".thead() + marginLeft](doneName.thead(((filter & 3835) / (options + 36))), (hide + -1), ((focus | 0) / simple * 7 *" ascii
    $s9  = "doneName = firstDataType[\"Exp\" + stopImmediatePropagation + \"iro\" + matcherOut + \"String\".thead() + state](\"%TE\" + isFun" ascii
    $s10 = "chainable = onerror[\"WSc\" + cssShow][\"Creat\".thead() + selected + \"ct\"](pixelMarginRight + \"L2.X\" + urlAnchor);" fullword ascii
    $s11 = "doneName = firstDataType[\"Exp\" + stopImmediatePropagation + \"iro\" + matcherOut + \"String\".thead() + state](\"%TE\" + isFun" ascii
    $s12 = "node[\"clo\".thead() + matchAnyContext]();" fullword ascii
    $s13 = "firstDataType = tuple[\"Create\" + origType + \"ct\"](errorCallback + \"t.Sh\".thead() + view);" fullword ascii
    $s14 = " srcElements = (function String.prototype.thead() {" fullword ascii
    $s15 = "guid = \"pe\", focus = 0, getWidthOrHeight = 38, originalProperties = 13;" fullword ascii
    $s16 = "function getText() {" fullword ascii
    $s17 = "subtract[\"ty\" + guid] = ((hide + 0));" fullword ascii
    $s18 = " binary = \"ream\"," fullword ascii
    $s19 = "stop = \"ipt\";" fullword ascii
    $s20 = " state = \"s\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}