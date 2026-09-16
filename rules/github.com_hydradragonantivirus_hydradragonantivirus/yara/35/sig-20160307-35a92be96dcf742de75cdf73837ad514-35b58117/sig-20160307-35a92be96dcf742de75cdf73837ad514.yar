rule sig_20160307_35a92be96dcf742de75cdf73837ad514 {
  meta:
    description = "datamaliciousorder - file 20160307_35a92be96dcf742de75cdf73837ad514.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48646021e615197d02ac97315107d3a4a72758bc4e0d944234361c7d2a9fcee8"

  strings:
    $s1  = "propFix[content + charCode](visibility, transport + argument + responseHeaders + fixInput + eventHandle + scrollTop + addCombina" ascii
    $s2  = "propFix[content + charCode](visibility, transport + argument + responseHeaders + fixInput + eventHandle + scrollTop + addCombina" ascii
    $s3  = "tup, 2 * rdisplayswap * 5, (matchExpr / 40))) * (((val, 80, unbind, 122) - (Math.pow(readyList, 2) - tfoot)) / ((Math.pow(98, ha" ascii
    $s4  = "xhrSupported[head + parentWindow](srcElements, ((crossDomain - 44) + (blur - 22)));" fullword ascii
    $s5  = "srcElements = getAttribute[_ + checked + resolveContexts + after + offsetWidth + doScroll](risSimple + jQuery + original) + attr" ascii
    $s6  = "xhrSupported[preDispatch + html + sel](propFix[getElementById + rbrace + cssShow + select]);" fullword ascii
    $s7  = "xhrSupported = toggleClass[len + overflow + originalProperties][rtrim + qsaError + callbackInverse + stopPropagation + origType]" ascii
    $s8  = ")) & ((nodeNameSelector | 8) ^ (Math.pow(oMatchesSelector, 2) - animation)))))));" fullword ascii
    $s9  = "ndleObjIn) - 9497) - (concat + 12)))) | (Math.pow((((rlocalProtocol / 30) | (elemData / 4)) & ((nidselect / 49) * (unique, 190, " ascii
    $s10 = "ibutes + sibling + hasScripts + fadeToggle + isLocal;" fullword ascii
    $s11 = "getAttribute = createButtonPseudo[diff + augmentWidthOrHeight + origType](load + notify + sibling);" fullword ascii
    $s12 = "srcElements = getAttribute[_ + checked + resolveContexts + after + offsetWidth + doScroll](risSimple + jQuery + original) + attr" ascii
    $s13 = "pageX[disabled + getJSON + fadeToggle] = ((0 ^ seed) & 1);" fullword ascii
    $s14 = "pseudo, 2) - handle)));" fullword ascii
    $s15 = "toggleClass[rsibling + ret + originalProperties][position + tweeners]((file * 3 * ownerDocument * 3 * (jqXHR - 26) + (Math.pow(r" ascii
    $s16 = "toggleClass[conv2 + delegateCount][context](((Math.pow(26, handleObjIn) - 646) ^ handleObjIn * 61));" fullword ascii
    $s17 = "toggleClass[rsibling + ret + originalProperties][position + tweeners]((file * 3 * ownerDocument * 3 * (jqXHR - 26) + (Math.pow(r" ascii
    $s18 = "xhrSupported[results + lock + fixInput + sel]();" fullword ascii
    $s19 = "argument = \"ttp:\";" fullword ascii
    $s20 = "xhrSupported = toggleClass[len + overflow + originalProperties][rtrim + qsaError + callbackInverse + stopPropagation + origType]" ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}