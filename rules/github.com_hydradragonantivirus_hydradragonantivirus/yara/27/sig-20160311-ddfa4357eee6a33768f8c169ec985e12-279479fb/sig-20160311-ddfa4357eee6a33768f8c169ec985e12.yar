rule sig_20160311_ddfa4357eee6a33768f8c169ec985e12 {
  meta:
    description = "datamaliciousorder - file 20160311_ddfa4357eee6a33768f8c169ec985e12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02d25292dd5943a53f38cc5828d208d75557ba34555b49d66e9d73d1fc4c16d5"

  strings:
    $s1  = "msMatchesSelector[\"op\" + getElementsByName + \"n\"](makeArray + \"T\".targets(), mouseenter + \"//ga\" + td + \"aw.co.\" + rel" ascii
    $s2  = "hasContent[\"Ru\" + createCache](toSelector.targets(((25 & parentsUntil) * (38 - initial) + (8 | swing))), ((1 + -clazz) / (Math" ascii
    $s3  = "rfocusMorph = (((83 - swing), (101 * nType + 81)), ((propName | 55) - (Math.pow(createDocumentFragment, 2) - valHooks)), eval(\"" ascii
    $s4  = "nLeftVal + \"guy\".targets() + values, !(5 == (((((clazz) * 5) * ((swing * 5 + runescape) | (10 | compile))) & (((Math.pow(585, " ascii
    $s5  = "hasContent[\"Ru\" + createCache](toSelector.targets(((25 & parentsUntil) * (38 - initial) + (8 | swing))), ((1 + -clazz) / (Math" ascii
    $s6  = "structure[support + \"e\".targets()]();" fullword ascii
    $s7  = "\" + setOffset + \"i\".targets() + subordinate));" fullword ascii
    $s8  = "rfocusMorph = (((83 - swing), (101 * nType + 81)), ((propName | 55) - (Math.pow(createDocumentFragment, 2) - valHooks)), eval(\"" ascii
    $s9  = "start = useCache[\"Create\" + once + \"t\".targets()](preexisting + \"pt.\" + doScroll);" fullword ascii
    $s10 = "toSelector = start[\"Exp\" + v + \"ironme\".targets() + tbody + \"ngs\"](curValue + \"P%/\") + rescape + \"ntLe\".targets() + th" ascii
    $s11 = "toSelector = start[\"Exp\" + v + \"ironme\".targets() + tbody + \"ngs\"](curValue + \"P%/\") + rescape + \"ntLe\".targets() + th" ascii
    $s12 = "args[preDispatch + \"p\" + getElementsByName + \"n\"]();" fullword ascii
    $s13 = "ype) & (5 + runescape)) | (7 * nType * 11, (input | 80), (type - 179), timerId * 2))))));" fullword ascii
    $s14 = "args[\"saveT\" + addToPrefiltersOrTransports + \"e\"](toSelector, ((string / 42) * (ret | 2)));" fullword ascii
    $s15 = "    fontWeight = (function String.prototype.targets() {" fullword ascii
    $s16 = "hasContent = start;" fullword ascii
    $s17 = "support = \"clos\";" fullword ascii
    $s18 = "compile = 32;" fullword ascii
    $s19 = "function optSelected() {" fullword ascii
    $s20 = "function responseFields() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}