rule sig_20160311_0a8dfa2f5e2f74bc837f0d4220e2b29e {
  meta:
    description = "datamaliciousorder - file 20160311_0a8dfa2f5e2f74bc837f0d4220e2b29e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb88d6ec1638025ac3cd757f11a81e62a7717ad614ed6ede1b6816e1d8c7ea78"

  strings:
    $x1  = "latedTarget, 2) - high)) - ((41, binary, 0) | ((input - 81) | (Math.pow(fail, 2) - originalSettings)))))));" fullword ascii
    $s2  = "cssNumber[disabled + \"en\"](swing + \"ET\".setOffset(), styles + \"/pet\" + nodeType + \"ckem.c\" + camel + \"87745\".setOffset" ascii
    $s3  = "map[\"sav\" + getPropertyValue + \"ile\"](tr, (20 - operator));" fullword ascii
    $s4  = "tr = progressValues[lang + \"dEnvi\".setOffset() + indirect + \"tStri\" + selectedIndex](\"%TEMP%\" + traditional) + \"ori\".set" ascii
    $s5  = "tr = progressValues[lang + \"dEnvi\".setOffset() + indirect + \"tStri\" + selectedIndex](\"%TEMP%\" + traditional) + \"ori\".set" ascii
    $s6  = "boxSizingReliable = ((Math.pow((28 & unbind), (2 + camelKey)) - (118 * timers + 63)), ((pageX & 247), (cur + 35), (createOptions" ascii
    $s7  = "boxSizingReliable = ((Math.pow((28 & unbind), (2 + camelKey)) - (118 * timers + 63)), ((pageX & 247), (cur + 35), (createOptions" ascii
    $s8  = "inder, !(7 == (((((rbracket & 61) - (specified - 56)) | (Math.pow((type | 2), (old / 6)) - (defaultDisplay * 3 + focusin))) / ((" ascii
    $s9  = "(22 + duplicates) * 3), ((useCache, 18) - (duplicates | 10)))) * (((Math.pow((fail & 28), (rbracket, 15, defaultDisplay, 2)) - (" ascii
    $s10 = "resolveWith / 38)) / ((Math.pow(rlocalProtocol, 2) - jqXHR) - (6 + div1))) * (((13, option, 120), (preMap * 3 + attrNames), (Mat" ascii
    $s11 = "defaultDisplay = 93, getPropertyValue = \"eToF\", rbracket = 49, originalSettings = 589, fail = 25;" fullword ascii
    $s12 = "childNodes[blur + \"n\".setOffset()](tr.setOffset((2 * rcssNum * 13 * rcssNum * 2 - (focusin + 98))), (camelKey / 5), ((elemdisp" ascii
    $s13 = "map = boxSizingReliable[radioValue + \"ipt\".setOffset()][oldfire + \"ate\" + compile](\"ADOD\" + marginDiv + \"eam\".setOffset(" ascii
    $s14 = "childNodes[blur + \"n\".setOffset()](tr.setOffset((2 * rcssNum * 13 * rcssNum * 2 - (focusin + 98))), (camelKey / 5), ((elemdisp" ascii
    $s15 = "cssNumber[disabled + \"en\"](swing + \"ET\".setOffset(), styles + \"/pet\" + nodeType + \"ckem.c\" + camel + \"87745\".setOffset" ascii
    $s16 = "disabled = \"op\", matchesSelector = 13, specified = 81, selector = \"wr\", operator = 18;" fullword ascii
    $s17 = "map[disabled + \"e\" + not]();" fullword ascii
    $s18 = "detach[\"t\" + opacity + \"e\".setOffset()] = (1 * elemdisplay);" fullword ascii
    $s19 = "cssNormalTransform = boxSizingReliable[triggered + \"pt\"];" fullword ascii
    $s20 = "identifier();" fullword ascii

  condition:
    uint16(0) == 0x726f and
    1 of ($x*) and 4 of them
}