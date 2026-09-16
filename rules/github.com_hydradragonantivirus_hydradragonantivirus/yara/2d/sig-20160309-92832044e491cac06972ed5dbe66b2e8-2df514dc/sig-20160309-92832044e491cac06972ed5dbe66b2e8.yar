rule sig_20160309_92832044e491cac06972ed5dbe66b2e8 {
  meta:
    description = "datamaliciousorder - file 20160309_92832044e491cac06972ed5dbe66b2e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4785687a2055c49d81caf7ef62e7497f259639aa7283937b9504071c6d292f82"

  strings:
    $s1  = "bind[cssShow + progressContexts](pattern + margin, optgroup + runescape + curOffset + propName + pixelMarginRight, !(((((71 | re" ascii
    $s2  = ") * ((1 * key) * (0 | firing)) + ((32 | getById) - (112 - siblingCheck))), ((20 * (firing ^ 7) + (tabIndex & 6)) ^ (Math.pow((rc" ascii
    $s3  = "method[input + getElementsByName][parse]((Math.pow((parent * 6 + buildParams), (5 - animated)) - (39532269 ^ namespace)));" fullword ascii
    $s4  = "leanScript + 64), (firing | 2)) - (checkNonElements + 15945))), (((whitespace & 127) + (responseText - 46)), ((modified - 68) + " ascii
    $s5  = "method = (((2 * tabIndex + 1) ^ (rbracket + 72)), (((key * 1) + -key), this));" fullword ascii
    $s6  = "insertBefore = max[context + isXMLDoc + dataTypes + fx + col + cors + letterSpacing](emptyGet + ap) + r20 + blur + dirrunsUnique" ascii
    $s7  = "onabort = method[input + isXMLDoc + getAll][optSelected + msFullscreenElement + rtagName + innerText](to + exports + promise + d" ascii
    $s8  = "onabort = method[input + isXMLDoc + getAll][optSelected + msFullscreenElement + rtagName + innerText](to + exports + promise + d" ascii
    $s9  = "insertBefore = max[context + isXMLDoc + dataTypes + fx + col + cors + letterSpacing](emptyGet + ap) + r20 + blur + dirrunsUnique" ascii
    $s10 = " + getAll + indirect;" fullword ascii
    $s11 = "max = step[bubbleType + stopped + node + getAll](specialEasing + subtract + ajaxSettings + value);" fullword ascii
    $s12 = "bind = method[specialEasing + subtract + getAll][getElementsByTagName + m + stopped + param](conv + addClass + combinator + capN" ascii
    $s13 = "bind = method[specialEasing + subtract + getAll][getElementsByTagName + m + stopped + param](conv + addClass + combinator + capN" ascii
    $s14 = "rnumnonpx[percent](insertBefore.optall(), ((1 | key) * (1 * returnTrue)), ((0 & key) ^ 0));" fullword ascii
    $s15 = "bind[ajaxSetup + hidden]();" fullword ascii
    $s16 = "onabort[token + _evalUrl + evt](insertBefore, 2);" fullword ascii
    $s17 = "boxSizingReliable = bind[soFar + ajaxHandleResponses + children + height];" fullword ascii
    $s18 = "bind[cssShow + progressContexts](pattern + margin, optgroup + runescape + curOffset + propName + pixelMarginRight, !(((((71 | re" ascii
    $s19 = "turnTrue) + 5), ((xml & 47) / (guaranteedUnique, 87, qsa, 13))) * ((((arr / 24), (fns / 44), (responseHeadersString * 5 + cache)" ascii
    $s20 = "step = method[charset + removeClass + getElementsByName];" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}