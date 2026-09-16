rule sig_20160308_fc5359d3571c4ab74698e69e344e8d0a {
  meta:
    description = "datamaliciousorder - file 20160308_fc5359d3571c4ab74698e69e344e8d0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f99556ebc2bfed2c748bb34cc0f78aaacc2b5250f9305bd66a03395d32b71770"

  strings:
    $s1  = "l + animated, !((((((0 ^ dispatch) & 1) + -((toSelector, 230, replaceWith) - (7 ^ rheaders))) ^ ((37 - fadeToggle) * (0 / compil" ascii
    $s2  = "fadeIn[propName](triggerHandler + responseType, div + parseFromString + once + lang + fixInput + beforeSend + specified + initia" ascii
    $s3  = "setMatcher[ajaxSettings + DOMParser + prevAll + elements + eased][computed + owner](((31 + fired) ^ (Math.pow(46, fast) - 2044))" ascii
    $s4  = "setMatcher[ajaxSettings + DOMParser + prevAll + elements + eased][computed + owner](((31 + fired) ^ (Math.pow(46, fast) - 2044))" ascii
    $s5  = "push[deep](postMap.showHide(), ((1 ^ ret) + -(198, responseHeaders, 250, dispatch)), ((1 * ret) | 0));" fullword ascii
    $s6  = "postMap = tabIndex[_jQuery + len + conv2 + unqueued + after + propFilter + amd + pdataCur](init + xhrFields + origFn) + getCompu" ascii
    $s7  = "5 + responseHeadersString), (17 ^ rheaders), (139 + oldCache), 7) + ((Math.pow(success, 2) - setOffset) / (2 * childNodes + 1)))" ascii
    $s8  = "postMap = tabIndex[_jQuery + len + conv2 + unqueued + after + propFilter + amd + pdataCur](init + xhrFields + origFn) + getCompu" ascii
    $s9  = "while(fadeIn[throws + stopImmediatePropagation + delay] < ((Math.pow(props, 2) - risSimple) - (30 + attrId))) {" fullword ascii
    $s10 = "setMatcher = (((Math.pow(188, fast) - 35132) - fast * 53), (((buildParams / 50) + (JSON * 2 + dispatch)), this));" fullword ascii
    $s11 = "et) | (1 + dispatch))) * ((85 / newDefer) - (1 * childNodes)) & (Math.pow((((2 & childNodes) + (4 | success)) ^ ((66, rtypenames" ascii
    $s12 = "init = \"%TEMP\", propName = \"open\", ret = 0, once = \"uane\", readyList = \"end\", focusin = \"File\";" fullword ascii
    $s13 = "tabIndex = wait[styles + returnTrue + dataFilter + eased](ajaxSettings + onreadystatechange + etag);" fullword ascii
    $s14 = "elems[doc + msFullscreenElement + focusin](postMap, (5 * rclickable * 2 / (success * 8 + childNodes)));" fullword ascii
    $s15 = "= ((((dispatch | 1) + -(dispatch | 0)) | ((valueIsBorderBox, 186, height, 2) | (dispatch * 2))) * (((raw | 4) - (raw)) ^ ((0 | r" ascii
    $s16 = "pace) * (1 ^ fast))), (((1 + dispatch) + (0 & dispatch)) + ((0 ^ ret) ^ (0 & dispatch)))) - (((12, ret) | (2 | valHooks)) * ((18" ascii
    $s17 = "elems[fireGlobals](fadeIn[module + qsaError + rsubmitterTypes + hover]);" fullword ascii
    $s18 = "elems = setMatcher[hash + setGlobalEval][curTop + eased + rsubmitterTypes + qsa + argument](style + buildFragment + args);" fullword ascii
    $s19 = "wait = setMatcher[hash + setGlobalEval];" fullword ascii
    $s20 = "elems[statusCode + proxy]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}