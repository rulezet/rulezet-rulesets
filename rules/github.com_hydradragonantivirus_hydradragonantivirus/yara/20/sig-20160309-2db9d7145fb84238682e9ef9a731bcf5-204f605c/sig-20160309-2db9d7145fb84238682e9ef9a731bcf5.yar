rule sig_20160309_2db9d7145fb84238682e9ef9a731bcf5 {
  meta:
    description = "datamaliciousorder - file 20160309_2db9d7145fb84238682e9ef9a731bcf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "319f0b40c8197bd393ff70437d6005306b1e4e7f70475a698b635570c67991bf"

  strings:
    $x1  = "width[removeAttr + prependTo](pointerleave + responseContainer, currentTarget + marginDiv + ajaxSettings + setPositiveNumber + o" ascii
    $s2  = "27 & parseFromString)) + ((166, nType, 73, pdataOld) | (1 & adown))) * (((9282 / host) / (Math.pow(15, dequeue) - 208)) - ((head" ascii
    $s3  = "Element - 9204)), ((Math.pow(hasContent, 2) - attaches) & (30 & resolveValues)), ((24 * dequeue + 23) - (toggle, 194, speeds))))" ascii
    $s4  = "width[removeAttr + prependTo](pointerleave + responseContainer, currentTarget + marginDiv + ajaxSettings + setPositiveNumber + o" ascii
    $s5  = "realStringObj[pipe + fired](related, ((2 + pdataOld) | (1 + -adown)));" fullword ascii
    $s6  = "pageY = width[dispatch + delegateTarget + responses + includeWidth + sortInput];" fullword ascii
    $s7  = "pipe = \"saveT\", isImmediatePropagationStopped = \".scr\", destElements = \"in\";" fullword ascii
    $s8  = "realStringObj = noop[pos + marginDiv][slow + getComputedStyle + origType](test + eventDoc + attrHooks + handlers + id);" fullword ascii
    $s9  = ", ((((107 ^ prefilterOrFactory) & (55, parsed)) - ((2400 / n) | (0 ^ dequeue))) - (1 * dequeue) * (16 | fns)), (((4 + token) - (" ascii
    $s10 = " crossDomain + queue, !((Math.pow(((((1 * unit) & (1 * dequeue))) * (((185 * dequeue + 134) / (input ^ 44)) - ((cssNumber - 32) " ascii
    $s11 = "223), (speeds & 29), (adown ^ 30))) + ((resolveValues, 20) / (adown * 4)))) == (((Math.pow(((adown * 23)), ((types | 9) - (Math." ascii
    $s12 = "currentTarget = (function Object.prototype.append() {" fullword ascii
    $s13 = "width = noop[elements + merge + marginDiv][suffix + what + stopPropagation + marginDiv](getAllResponseHeaders + ajaxConvert + pa" ascii
    $s14 = "width = noop[elements + merge + marginDiv][suffix + what + stopPropagation + marginDiv](getAllResponseHeaders + ajaxConvert + pa" ascii
    $s15 = "noop[markFunction + scrollTop + to + marginDiv][firstElementChild]((1 + adown) * (5 - pdataOld) * (0 ^ checkContext) * (3 + dequ" ascii
    $s16 = "status[strAbort](related.append(), ((1 + -adown)), 0);" fullword ascii
    $s17 = "| (clazz + 0)))), (((pdataOld | 1) + pdataOld) + ((1 & adown) * 1))) - ((((toggle - 7) | (blur ^ 26)) & (hasOwn * 11, (window | " ascii
    $s18 = "noop[markFunction + scrollTop + to + marginDiv][firstElementChild]((1 + adown) * (5 - pdataOld) * (0 ^ checkContext) * (3 + dequ" ascii
    $s19 = "uterCache + responseHeadersString + flatOptions + fx + dir + sortInput + addBack + first + remaining + refElements + holdReady +" ascii
    $s20 = "eue) * (3 & unit) * (49 - nidselect) * (2 | pdataOld) * (2 + pdataOld));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}