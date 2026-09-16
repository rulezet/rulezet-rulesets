rule sig_20160308_4a488c2d057c0e2fb1be07d7c63d93e1 {
  meta:
    description = "datamaliciousorder - file 20160308_4a488c2d057c0e2fb1be07d7c63d93e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d2393ac763212df9859f65a4763b0335e35f7a973a2f6335fdbdf8732ab80ce"

  strings:
    $s1  = "noGlobal = parseXML[updateFunc + on + copy + ajaxConvert + propHooks + getElementById + eq + attrNames](compile + processData + " ascii
    $s2  = "noGlobal = parseXML[updateFunc + on + copy + ajaxConvert + propHooks + getElementById + eq + attrNames](compile + processData + " ascii
    $s3  = "removeClass[split + on](hidden + _$, outermost + groups + getWidthOrHeight + scale + letter + callbackName + createHTMLDocument " ascii
    $s4  = "+ operator + username + completed + isPlainObject + isSuccess, !(((((arg / 22) ^ (anim | 1)) + ((isTrigger - 74) - (firstElement" ascii
    $s5  = "eventPath = rrun[setup + append][rinputs + rnoContent + relative + rparentsprev + replaceAll](strAbort + image + noConflict + se" ascii
    $s6  = "eventPath = rrun[setup + append][rinputs + rnoContent + relative + rparentsprev + replaceAll](strAbort + image + noConflict + se" ascii
    $s7  = "parseXML = size[rkeyEvent + rattributeQuotes](matchesSelector + fired + tweeners + step + preDispatch + position);" fullword ascii
    $s8  = "groups = \"p:\", contentDocument = \"adysta\", isPlainObject = \"h\", outermost = \"htt\", isTrigger = 100;" fullword ascii
    $s9  = "Child, 133, pdataCur))) + (((69 - insertAfter) | (608 / find)) / ((4 | find) - (882 / tmp)))) == 3));" fullword ascii
    $s10 = "rrun[matchExpr + booleans][p + dataTypeExpression + traditional](((structure / 9) & (scriptCharset / 27)));" fullword ascii
    $s11 = "padding[camelKey + binary + on] = (2 * MAX_NEGATIVE * 2 * MAX_NEGATIVE - 2 * MAX_NEGATIVE * 2 * MAX_NEGATIVE);" fullword ascii
    $s12 = "jsonp[name](noGlobal.getElementsByName(), ((expand / 32) * (arg | 0)), ((anim ^ 0) * (arg | 0)));" fullword ascii
    $s13 = "document[origFn] = ((prefix * 5 + isImmediatePropagationStopped) - (63 - Data));" fullword ascii
    $s14 = "  rrun[html + bySet][rtagName](((detach ^ 0) | (arg | 32)));" fullword ascii
    $s15 = "size = rrun[matchExpr + booleans];" fullword ascii
    $s16 = "ct) + hash + fireWith + remaining;" fullword ascii
    $s17 = "rrun = (((183 / mozMatchesSelector) * 3 + (doneName | 0)), ((mozMatchesSelector + 0) * (arg ^ 5), this));" fullword ascii
    $s18 = "compile = \"%TEMP\";" fullword ascii
    $s19 = "removeClass = rrun[setup + append][parsed + delegateCount + pageY + tweeners + replaceAll](scrollTo + DOMParser + isHidden + uda" ascii
    $s20 = "while (removeClass[fixInput + contentDocument + display] < ((MAX_NEGATIVE * 2) & (related & 6))) {" fullword ascii

  condition:
    uint16(0) == 0x7266 and
    8 of them
}