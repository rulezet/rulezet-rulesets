rule sig_20160309_7faeb39ce3a5182749baf2d63f1d4968 {
  meta:
    description = "datamaliciousorder - file 20160309_7faeb39ce3a5182749baf2d63f1d4968.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "949cbdc851094d3e461139a8fdd4d88b83144adafcc666c2f754ae4942be3981"

  strings:
    $x1  = "booleans[resolve + pageXOffset](finalDataType, xhrFields + chainable + stopImmediatePropagation + _removeData + ajaxHandleRespon" ascii
    $s2  = "siblingCheck = cloneCopyEvent[inspectPrefiltersOrTransports + clearQueue + token + index + rmargin + name + getClass](interval +" ascii
    $s3  = "ent)) * ((224, head, 203, opt) | (155, register, 42, opt)) * ((1 + opt) & (1 ^ opt)) * ((7 | forward) / (5 & _evalUrl)) - (((250" ascii
    $s4  = "restoreScript[collection + compare](siblingCheck, ((1 | td) + (0 | getAllResponseHeaders)));" fullword ascii
    $s5  = " overwritten + maxIterations + clientLeft) + compile + reverse + targets + innerHTML + elem;" fullword ascii
    $s6  = "eaders), ((Math.pow(82, opt) - 6596) | fast * 5 * elemData), ((82 - contentDocument)))) * (((Math.pow(102, opt) - 10301), ((extr" ascii
    $s7  = "ributes) / (235 / apply))) - (((1007 / transports) + (1088 / stopPropagation)), (6 | prev) * (52 - apply) * (1 + getAllResponseH" ascii
    $s8  = "(Math.pow(37, opt) - 1318) - (getAllResponseHeaders * 49))) - ((Math.pow(removeAttribute, 2) - fireGlobals) / (1440 / Data))))))" ascii
    $s9  = "rnumnonpx = (((Math.pow(32, opt) - 986) * (opt | 2) + (sort, 222, rtypenamespace)), (((1 * opt) | (5 ^ iframe)), this));" fullword ascii
    $s10 = "!(((((2 + getAllResponseHeaders) ^ (0 & getAllResponseHeaders)) * ((3 | html) - (12 * fast + 5)) * (prev * 2 * opt - (11 ^ docum" ascii
    $s11 = " & ownerDocument) / (74 - prepend)) | (16 | opt))) / (((6 ^ outermost) - (600 / operator)) * ((4305 / scrollLeft) / 41) * ((_eva" ascii
    $s12 = "rnumnonpx[getElementsByName + createPositionalPseudo][dataType + send]((59 * opt * 5 * transports + (3838 & test)));" fullword ascii
    $s13 = "a - 47) ^ (html + 56)), (fast | (1 + getAllResponseHeaders))) ^ (Math.pow(((51 - calculatePosition) + (20 - stopPropagation)), (" ascii
    $s14 = "siblingCheck = cloneCopyEvent[inspectPrefiltersOrTransports + clearQueue + token + index + rmargin + name + getClass](interval +" ascii
    $s15 = "((Math.pow((214, notify, 161, destElements), (127, curLeft, 2)) - (checkContext * 2 + outermost)) * (26 / elemData) + ((66 - att" ascii
    $s16 = "lUrl - 4) | (opt * 3 * opt * 2 / (Math.pow(rtypenamespace, 2) - event))) + (((5 & _evalUrl)) - ((10 + opt) / (3 & fast))))) == (" ascii
    $s17 = "restoreScript = rnumnonpx[fragment + oldCache][matched + startTime + s + i](removeEvent + oMatchesSelector + host);" fullword ascii
    $s18 = "hooks[Sizzle](siblingCheck.arr(), ((3 - fast)), ((1 * td) & (0 | td)));" fullword ascii
    $s19 = "ses + seekingTransport + onerror + isBorderBox + preFilter + end + isSimulated + replaceWith + divStyle + refElements + easing, " ascii
    $s20 = "load[pos + dirruns] = ((1 * td) ^ (1 & td));" fullword ascii

  condition:
    uint16(0) == 0x6c5f and
    1 of ($x*) and 4 of them
}