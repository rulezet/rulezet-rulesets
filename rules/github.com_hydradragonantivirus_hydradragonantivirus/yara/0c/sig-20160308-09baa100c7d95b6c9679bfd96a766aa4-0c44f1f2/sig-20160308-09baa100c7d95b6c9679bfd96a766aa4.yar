rule sig_20160308_09baa100c7d95b6c9679bfd96a766aa4 {
  meta:
    description = "datamaliciousorder - file 20160308_09baa100c7d95b6c9679bfd96a766aa4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08dc255513ced38ca73ea6d709be0482fcf255ed7ef5a70c4ef1db173410338c"

  strings:
    $s1  = "    firstChild[curTop + sortOrder + to][processData + getWidthOrHeight](((Math.pow(102, param) - 10288) & (scrollTop + 51)));" fullword ascii
    $s2  = "unbind[finalValue + has + preFilters + nonce](marginRight, ((param * 3 + getElementsByTagName) - 5));" fullword ascii
    $s3  = " 1))) - (((progressContexts * 2) + param) ^ ((Math.pow(32, param) - 977) - (elemLang & 0))))) == getElementsByTagName));" fullword ascii
    $s4  = "l[Data](marginRight.compile(), ((selectors * 3) - selectors * 3), (crossDomain - 8));" fullword ascii
    $s5  = "funcName[teardown](done + hide, writable + finalText + orig + self + byElement + curElem + class2type, !(((((param * 2 * uniqueS" ascii
    $s6  = "ort * (45 - serialize) + 6), ((Math.pow(isXMLDoc, 2) - detach) - (252, offset)), ((159 & createComment)), ((1 * elemLang) ^ (1 &" ascii
    $s7  = "detach = 61234, progressContexts = 6, specified = \"d\", processData = \"S\";" fullword ascii
    $s8  = "stopped[rcomma + curCSSTop + removeEvent] = ((elemLang | 46) - (serialize | 4));" fullword ascii
    $s9  = "funcName = firstChild[curTop + doneName][inspectPrefiltersOrTransports + clientY + expanded + optSelected](version + matcher + n" ascii
    $s10 = "funcName = firstChild[curTop + doneName][inspectPrefiltersOrTransports + clientY + expanded + optSelected](version + matcher + n" ascii
    $s11 = "while(funcName[rbuggyQSA + specified + delay + origCount + replaceWith + responseText] < (74 / getAttribute) * (1 + getElementsB" ascii
    $s12 = "while(funcName[rbuggyQSA + specified + delay + origCount + replaceWith + responseText] < (74 / getAttribute) * (1 + getElementsB" ascii
    $s13 = " getElementsByTagName))) * (((1 * getElementsByTagName) * (76, getElementsByTagName)) * ((30, write) / (17 ^ scrollTop)))) | (((" ascii
    $s14 = "firstChild = ((3 * success - (369 - traditional)), (((1 + elemdisplay) / (2 * param + 1)), this));" fullword ascii
    $s15 = "unbind[pixelMarginRight + implicitRelative]();" fullword ascii
    $s16 = "firstChild[split + rxhtmlTag + to][arg + rxhtmlTag](((tokens / 48), (startLength, 125, prop), (315000 / styles)));" fullword ascii
    $s17 = "unbind[conv2 + responseText](funcName[emptyStyle + byElement + remove + $ + delay]);" fullword ascii
    $s18 = "var dataTypeExpression = (function String.prototype.compile() {" fullword ascii
    $s19 = "rnamespace = cssHooks[cors + bulk + nonce + optSelected](curTop + unmatched + matchesSelector);" fullword ascii
    $s20 = "cssHooks = firstChild[fadeOut + eq + swing];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}