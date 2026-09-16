rule sig_20160307_a428fc3ab83dbb1f39acbfcb3bf28498 {
  meta:
    description = "datamaliciousorder - file 20160307_a428fc3ab83dbb1f39acbfcb3bf28498.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f66baf7ba07a2fab713c16b06e5f2014a8bfc55f06a7f11c0cb0e27062aac513"

  strings:
    $s1  = "elemLang[processData + username](xhrFields + last, when + getBoundingClientRect + keyHooks + div + first + off + cssProps + hash" ascii
    $s2  = "combinator[xhrSupported](args.dataAndEvents(), ((30, xml, 27, propFilter) / (190, dataShow, 76, postFinder)), (19 - marginDiv));" ascii
    $s3  = "elemLang[processData + username](xhrFields + last, when + getBoundingClientRect + keyHooks + div + first + off + cssProps + hash" ascii
    $s4  = "subordinate[top + createPseudo + response][matcherFromTokens]((matcher - 11) * ifModified * (1 * hold) * (93, curValue, 69, ifMo" ascii
    $s5  = "clearTimeout[rmsPrefix + finish + safeActiveElement + ajaxConvert](args, ((nType + 0) - (Math.pow(slideDown, 2) - rsubmitterType" ascii
    $s6  = "subordinate[top + createPseudo + response][matcherFromTokens]((matcher - 11) * ifModified * (1 * hold) * (93, curValue, 69, ifMo" ascii
    $s7  = "clearTimeout[rmsPrefix + finish + safeActiveElement + ajaxConvert](args, ((nType + 0) - (Math.pow(slideDown, 2) - rsubmitterType" ascii
    $s8  = "subordinate = (((1 * ifModified) | (131, hold, 64)), (((clientLeft * 4) + (Math.pow(speeds, 2) - fadeIn)), this));" fullword ascii
    $s9  = "target = \"w\"," fullword ascii
    $s10 = "clearTimeout[target + cleanData](elemLang[unloadHandler + nid + always + setter + escapedWhitespace]);" fullword ascii
    $s11 = "clearTimeout = subordinate[dest + fire + jQuery + filters][expand + charCode + dataTypeExpression + key](dataAttr + suffix + cur" ascii
    $s12 = "callback[timeStamp + setter + username] = ((matcher - 12) * (propFilter & 1));" fullword ascii
    $s13 = "clearTimeout = subordinate[dest + fire + jQuery + filters][expand + charCode + dataTypeExpression + key](dataAttr + suffix + cur" ascii
    $s14 = "qualifier = pixelMarginRightVal[removeEventListener + _queueHooks + iframe + key](top + offset + indirect + rbracket + rcssNum +" ascii
    $s15 = "qualifier = pixelMarginRightVal[removeEventListener + _queueHooks + iframe + key](top + offset + indirect + rbracket + rcssNum +" ascii
    $s16 = ")))) - ((((Math.pow(close, 2) - jsonpCallback) - (75 - val)) ^ ((192 | cssNumber) ^ (2162 ^ then))) / (((8 * elemData + 6) + (cl" ascii
    $s17 = "ajaxConvert = \"ile\", unique = \"dE\", fns = \"ipt\", getter = \"Ob\", val = 58;" fullword ascii
    $s18 = "elemLang = subordinate[dest + fns][Symbol + getter + prependTo](cached + isXMLDoc + rfxtypes + documentElement + adjusted);" fullword ascii
    $s19 = "fied & (1 * elemData)) + ((1 + -clientLeft) | 0)) + (((method, 60, num, 1) + -(clientLeft & 1)) / (elemData * 3 + (newCache | 5)" ascii
    $s20 = "subordinate[top + eventPath][rjsonp + dataType](((rnative ^ 4427) / (slideDown * 3)));" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}