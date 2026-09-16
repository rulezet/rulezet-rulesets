rule sig_20160308_733a8907808f0b2b2e27ddd073e01275 {
  meta:
    description = "datamaliciousorder - file 20160308_733a8907808f0b2b2e27ddd073e01275.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "874406b778f380471a25ebe8724f59aed3966a8e82a74864ae4c16e6bf94dc4f"

  strings:
    $s1  = "compile[overwritten + timeoutTimer + Sizzle + active] = ((replaceWith * 0) / (getBoundingClientRect - 32));" fullword ascii
    $s2  = "self[delegate + emptyStyle][keyHooks + dataTypes + isNumeric](((Math.pow(14568, responseType) - 212211624) & (fired * 4 + boxSiz" ascii
    $s3  = "self[delegate + emptyStyle][keyHooks + dataTypes + isNumeric](((Math.pow(14568, responseType) - 212211624) & (fired * 4 + boxSiz" ascii
    $s4  = "subtract = Deferred[parseJSON + combinator + timeoutTimer](rcheckableType + keyHooks + grep + height + attrHooks + fixHooks);" fullword ascii
    $s5  = "handler[special](parseOnly + stored, progressContexts + support + nidselect + holdReady + eventPath + rquery + duplicates + time" ascii
    $s6  = "while(handler[rscriptType + originalEvent + scrollLeft + fnOut + setOffset] < ((oMatchesSelector | 1) * responseType * 2)) {" fullword ascii
    $s7  = "self = (((132 - tfoot) & (2 | constructor)), (((124, fadeIn, 9) + (replaceWith + 0)), this));" fullword ascii
    $s8  = "getBoundingClientRect = 79, wrap = \"2.XMLH\", elem = \"sp\", originalEvent = \"y\", keyHooks = \"S\", event = \"send\";" fullword ascii
    $s9  = "camelKey[cache + content + handle](rxhtmlTag, ((replaceWith ^ 3) + oMatchesSelector));" fullword ascii
    $s10 = "camelKey = self[matches + timeoutTimer][reject + expando + risSimple](finalValue + _removeData + getClass + s + ajaxTransport);" fullword ascii
    $s11 = ") * 1)) * (((anim - 19) - (augmentWidthOrHeight)) * ((238, collection, 62) / docElem)))) > 1));" fullword ascii
    $s12 = "self[rcheckableType + reliableMarginRight + emptyStyle][keyHooks + beforeSend + preexisting + node](((minWidth ^ 47) ^ (start, 1" ascii
    $s13 = "self[rcheckableType + reliableMarginRight + emptyStyle][keyHooks + beforeSend + preexisting + node](((minWidth ^ 47) ^ (start, 1" ascii
    $s14 = " + node + transports + dataType + file + checked + parentNode + container + insertAfter, !(((((replaceWith & 0) | (oMatchesSelec" ascii
    $s15 = "handler[special](parseOnly + stored, progressContexts + support + nidselect + holdReady + eventPath + rquery + duplicates + time" ascii
    $s16 = "}, 10), finalValue = \"AD\", content = \"oF\";" fullword ascii
    $s17 = "handler = self[matches + timeoutTimer][clientLeft + gotoEnd + remaining](valueParts + wrap + closest);" fullword ascii
    $s18 = "ifModified[timeoutTimer + originalEvent + match] = 1;" fullword ascii
    $s19 = "Deferred = self[bubbleType + responseContainer];" fullword ascii
    $s20 = "support = \"/la\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}