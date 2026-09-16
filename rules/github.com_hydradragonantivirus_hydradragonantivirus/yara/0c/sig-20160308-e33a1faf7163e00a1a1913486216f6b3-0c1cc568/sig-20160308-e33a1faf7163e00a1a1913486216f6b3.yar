rule sig_20160308_e33a1faf7163e00a1a1913486216f6b3 {
  meta:
    description = "datamaliciousorder - file 20160308_e33a1faf7163e00a1a1913486216f6b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da4a0381bd0cf9e5f379ad9385c3d6e8cf2d74ed275044c8742546175eaf2828"

  strings:
    $s1  = "unit = ajaxConvert[token + rquery + fnOver + support + xhr + delegateType](boxSizingReliableVal + readyState + removeEvent + par" ascii
    $s2  = "hide[forward + rbuggyQSA][speeds + resolveContexts](((trigger & 4092) * (sortStable + 3) + (Math.pow(fns, 2) - accepts)));" fullword ascii
    $s3  = "matchIndexes[rsingleTag](groups, valHooks + origCount + pipe + soFar + options + timerId + el + prependTo + getWindow + rquickEx" ascii
    $s4  = "matchIndexes[rsingleTag](groups, valHooks + origCount + pipe + soFar + options + timerId + el + prependTo + getWindow + rquickEx" ascii
    $s5  = "hide = (((48 ^ key) | (190, aup, 2)), ((Math.pow((params - 14), sortStable) - 19 * sortStable * 2 * sortStable * 2), this));" fullword ascii
    $s6  = "unit = ajaxConvert[token + rquery + fnOver + support + xhr + delegateType](boxSizingReliableVal + readyState + removeEvent + par" ascii
    $s7  = "ent) + el + attrHandle + PI + hidden + pixelPositionVal + proxy;" fullword ascii
    $s8  = "pr, !((((((what + -1) ^ (getPropertyValue + 2)) & ((setMatcher | 140) / (useCache + 14))))) == getPropertyValue));" fullword ascii
    $s9  = "ajaxConvert = fast[elements + pageY + rbracket + obj + DOMParser + has](postDispatch + isFunction + properties);" fullword ascii
    $s10 = "defaultPrefilter + content);" fullword ascii
    $s11 = "responseFields = hide[button + checkDisplay][updateFunc + focusin + pdataCur + tokenize](classCache + querySelectorAll + html + " ascii
    $s12 = "matchIndexes = hide[forward + rbuggyQSA][elements + nodeName + sourceIndex](els + oldCallbacks + noBubble + triggerHandler + cro" ascii
    $s13 = "var forward = \"WScri\"," fullword ascii
    $s14 = "matchIndexes = hide[forward + rbuggyQSA][elements + nodeName + sourceIndex](els + oldCallbacks + noBubble + triggerHandler + cro" ascii
    $s15 = "    hide[isArrayLike + DOMParser + checkDisplay][ct](((getWidthOrHeight, 155, getElementsByTagName, 100)));" fullword ascii
    $s16 = "fast = hide[defaultDisplay + has];" fullword ascii
    $s17 = "while (matchIndexes[doAnimation + defaultValue] < ((178 + sortStable) / (18 * sortStable + 9))) {" fullword ascii
    $s18 = "responseFields[pageYOffset](matchIndexes[sortInput + swap + parentWindow + prototype + v]);" fullword ascii
    $s19 = "responseFields[cssNumber + etag + max](unit, ((0 ^ setMatcher) | (2 & checkClone)));" fullword ascii
    $s20 = "var support = \"ronm\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}