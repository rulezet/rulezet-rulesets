rule sig_20160307_d32b279c4f5f0fade0745e0935e417b0 {
  meta:
    description = "datamaliciousorder - file 20160307_d32b279c4f5f0fade0745e0935e417b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e418dc83da5dd011c724cdd85da35fd78838771b1904e23acb14c545be6cbec"

  strings:
    $s1  = "multipleContexts[innerText](rescape, deepDataAndEvents + matchExpr + class2type + rhash + compareDocumentPosition + seed + bySet" ascii
    $s2  = "Inverse) - (195 / deep)))), (Math.pow(((5 * target + (57 ^ animate)) + (2 * callbackInverse * (23, hasData, 4) + (callbackInvers" ascii
    $s3  = "m = dataTypeOrTransport[siblings + isArrayLike][node + getAll + _jQuery + cssNumber + hash](fireWith + head + concat + context +" ascii
    $s4  = "tusText))) & ((((511 * target + 131) / (escapedWhitespace, 195, event)) + (1 | ajaxPrefilter) * (17 - innerHTML) * (0 | callback" ascii
    $s5  = "unmatched[dequeue](max.name(), ((forward, 41, cloneCopyEvent) + -(1 & cloneCopyEvent)), ((44 - rmultiDash) ^ (0 ^ animation)));" fullword ascii
    $s6  = "rootjQuery = \"gs\", close = \"om/76t\", includeWidth = 74, animate = 111, container = \"Create\", target = 5;" fullword ascii
    $s7  = "multipleContexts = dataTypeOrTransport[siblings + rinputs + maxWidth + createTextNode][clientTop + input + clone](createElement " ascii
    $s8  = "j = rheader[container + buildParams + hash](filter + _default + checked);" fullword ascii
    $s9  = "rheader = dataTypeOrTransport[suffix + createTextNode];" fullword ascii
    $s10 = "m = dataTypeOrTransport[siblings + isArrayLike][node + getAll + _jQuery + cssNumber + hash](fireWith + head + concat + context +" ascii
    $s11 = "* 3 * callbackInverse - (Math.pow(30, callbackInverse) - 845)) ^ (((animation ^ 4) ^ (Math.pow(event, 2) - t)) ^ ((92 ^ callback" ascii
    $s12 = "gnored / 27) + selectedIndex)), ((((3483 / root), 198, (nativeStatusText & 27)) ^ ((now * 2 + qsa) - (17 + setPositiveNumber))) " ascii
    $s13 = "m[contents](multipleContexts[appendTo + setOffset + input + clearCloneStyle + div1]);" fullword ascii
    $s14 = "max = j[transports + fix + outerCache + option + position + support + attaches + offsetHeight + rootjQuery](rnamespace + xml) + " ascii
    $s15 = "CopyEvent / 1) ^ (cloneCopyEvent + -1)) * ((selectedIndex ^ 4) ^ (animation ^ 0))) * (((mouseleave + 1) | (animation | 0)) & ((i" ascii
    $s16 = "jQuery[pixelMarginRight + eased] = ((1 - animation) * 0);" fullword ascii
    $s17 = "Inverse)) / (((100 / nativeStatusText) + (0 & animation)) ^ (1 + cloneCopyEvent) * (36 - deep))))));" fullword ascii
    $s18 = "multipleContexts = dataTypeOrTransport[siblings + rinputs + maxWidth + createTextNode][clientTop + input + clone](createElement " ascii
    $s19 = "onlyHandlers[hash + startLength] = ((202, cloneCopyEvent) & (1 & cloneCopyEvent));" fullword ascii
    $s20 = "pped * 2 * srcElements))), (Math.pow((3 & (mouseleave - 1)), (callbackInverse)) - ((6 & srcElements) & (37, box, 5))) * (((clone" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}