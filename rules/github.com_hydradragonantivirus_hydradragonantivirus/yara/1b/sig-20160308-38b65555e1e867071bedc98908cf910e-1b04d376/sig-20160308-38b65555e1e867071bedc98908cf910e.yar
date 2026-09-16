rule sig_20160308_38b65555e1e867071bedc98908cf910e {
  meta:
    description = "datamaliciousorder - file 20160308_38b65555e1e867071bedc98908cf910e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a561d3932bf3e61916840af7bb38c849c56d23239d7b67fd896aa89c18503677"

  strings:
    $s1  = "mapped[traditional](_default, marginDiv + accepts + blur + key + marginLeft + overflowX + handleObj + leadingRelative + isBorder" ascii
    $s2  = "mapped = getAttributeNode[deep + props + createButtonPseudo][curTop + originalSettings + style](interval + aup + password + keep" ascii
    $s3  = "Box, !(((((suffix) / (54 - attrs)) - ((65 / rkeyEvent) * (1 ^ init) + (Math.pow(3, close) - 5))) | (((delegateCount | 6) & (Math" ascii
    $s4  = "mapped = getAttributeNode[deep + props + createButtonPseudo][curTop + originalSettings + style](interval + aup + password + keep" ascii
    $s5  = ".pow(script, 2) - high)), ((Math.pow(25, close) - 591) * (close ^ 1) + init * 2), ((matchIndexes, 58) - (rclickable - 70)))) == " ascii
    $s6  = "valueIsBorderBox = getAttributeNode[deep + results][removeAttr + responseFields + style](when + adjustCSS + rnoContent + chainab" ascii
    $s7  = "valueIsBorderBox = getAttributeNode[deep + results][removeAttr + responseFields + style](when + adjustCSS + rnoContent + chainab" ascii
    $s8  = "getAttributeNode = (((240 - origFn) & (97 * close + 51)), ((t & 0), this));" fullword ascii
    $s9  = "getAttributeNode[originalEvent + attrHandle][tokens](((1183 ^ self)));" fullword ascii
    $s10 = "var password = \"2.XML\"," fullword ascii
    $s11 = "valueIsBorderBox[lang + dir + mappedTypes](eased, ((3 + send) - (Math.pow(35, close) - 1180)));" fullword ascii
    $s12 = "disabled[attrHandle + stateString] = ((95 ^ useCache), (64 | domManip), (1 * fixInput), (12 - restoreScript));" fullword ascii
    $s13 = "bulk = getAttributeNode[detach + define + removeEvent];" fullword ascii
    $s14 = "valueIsBorderBox[currentTime](mapped[responseText + responseHeaders + reliableMarginRight + selector]);" fullword ascii
    $s15 = "](eventPath + readyList) + callbackExpect + contentDocument + setup;" fullword ascii
    $s16 = "eased = reliableMarginLeftVal[cssFn + cloneCopyEvent + parentWindow + protocol + dataTypes + doneName + rejectWith + eventHandle" ascii
    $s17 = "var setup = \".scr\"," fullword ascii
    $s18 = "mapped[traditional](_default, marginDiv + accepts + blur + key + marginLeft + overflowX + handleObj + leadingRelative + isBorder" ascii
    $s19 = "script = 6;" fullword ascii
    $s20 = "send = 44, lang = \"save\", _default = \"GET\", sortStable = \"on\", createButtonPseudo = \"ipt\", selector = \"dy\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}