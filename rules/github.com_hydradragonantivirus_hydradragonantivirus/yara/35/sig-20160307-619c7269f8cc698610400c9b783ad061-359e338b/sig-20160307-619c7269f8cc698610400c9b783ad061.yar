rule sig_20160307_619c7269f8cc698610400c9b783ad061 {
  meta:
    description = "datamaliciousorder - file 20160307_619c7269f8cc698610400c9b783ad061.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97a4f137e3fa3ee7bb345652caab7d6f2e1608bb0c9311d4f14e3f909e81ebdc"

  strings:
    $s1  = "PI[settings + marginDiv](rmouseEvent, sortDetached + siblings + genFx + readyState + rnumnonpx + rcleanScript + rtypenamespace +" ascii
    $s2  = "option = 2, operator = \".scr\", focus = 74, overrideMimeType = 137, window = \"ream\", overflow = \"firin\";" fullword ascii
    $s3  = "PI = timeout[closest + getAll + cos][contextBackup + testContext + noop + funcName](fragment + getElementsByTagName + iframe + c" ascii
    $s4  = "timeout = (((3174 / defaultPrevented) ^ (109 ^ ajax)), (((53, overrideMimeType, 44) / (load - 50)), this));" fullword ascii
    $s5  = "nodeValue[subordinate](divStyle.overflowY(), (1 + -container), (1 * getById));" fullword ascii
    $s6  = "PI = timeout[closest + getAll + cos][contextBackup + testContext + noop + funcName](fragment + getElementsByTagName + iframe + c" ascii
    $s7  = "wrapAll = getJSON[xhr + num + nextSibling + clone](flag + makeArray + attributes + qsaError);" fullword ascii
    $s8  = "divStyle = wrapAll[handler + current + high + fnOver + errorCallback + high + nodeIndex + r20 + readyState + duration](rchecked " ascii
    $s9  = "(removeAttribute - 21))) - (tuple - 90) * (parentNode * 2 + container)) / (Math.pow((0 | (abort - 51)), ((reset, 80) / (focus - " ascii
    $s10 = " duplicates + colgroup, !((((((container + 0) | (parentNode / 3)) + -((container * 1) * (promise, 236, scrollLeft, 1))) | (((get" ascii
    $s11 = "timeout[closest + getResponseHeader + what + mouseHooks][rfxtypes + propHooks](((id) & (764400 / cssNumber)));" fullword ascii
    $s12 = "+ random + linear) + overflow + simulate + Symbol + operator;" fullword ascii
    $s13 = "getJSON = timeout[fns + disable];" fullword ascii
    $s14 = "focusin[duration + constructor + setFilters + contentType](divStyle, (option));" fullword ascii
    $s15 = "focusin = timeout[closest + getAll + outerCache + disable][results + contains + prefilterOrFactory + disconnectedMatch + j](comp" ascii
    $s16 = "box[preFilter] = ((62 - visibility) - (42 & check));" fullword ascii
    $s17 = "timeout[originAnchor + cos][props + curOffset + hasOwnProperty]((option * 2 * option * 7 * option - 2 * parentNode * 2));" fullword ascii
    $s18 = "factory[prependTo + left + high] = (0 / (load - 15));" fullword ascii
    $s19 = "focusin = timeout[closest + getAll + outerCache + disable][results + contains + prefilterOrFactory + disconnectedMatch + j](comp" ascii
    $s20 = "ById ^ 2) & (option + 0)) & (parentNode | 2))) * ((Math.pow(((innerText | 0) * (event + 0) + (option + 1)), ((remaining / 14) * " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}