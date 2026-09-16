rule sig_20160308_9dad387920af039f667636ced671bb78 {
  meta:
    description = "datamaliciousorder - file 20160308_9dad387920af039f667636ced671bb78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb5aaf1fe18f02fc3eefffc7b678032634c8fc52515a833754f84a87f6d4a615"

  strings:
    $x1  = "outerCache[camelCase](parseXML, triggered + second + second + what + valHooks + cache + hasCompare + toggleClass + define + getW" ascii
    $s2  = "e) - 5) & (pipe, 103, password, 7)))) ^ (((class2type, 172, isImmediatePropagationStopped, 0) ^ (curPosition & 1)) * selectors) " ascii
    $s3  = "noop = delegateType[currentTarget + parentOffset + related][defineProperty + curElem + bySet + next](keys + offset + register + " ascii
    $s4  = "noop = delegateType[currentTarget + parentOffset + related][defineProperty + curElem + bySet + next](keys + offset + register + " ascii
    $s5  = "delegateType[currentTarget + style + to + handler][hold + detach](((64 ^ rattributeQuotes) & (2 * contains + 1)));" fullword ascii
    $s6  = "* ((Math.pow((47 & rprotocol), (2 | cloneCopyEvent)) - (44 | originalEvent)) - (186, camelKey, 5) * (cloneCopyEvent | 2) * (chil" ascii
    $s7  = "delegateType = (((46, rscriptTypeMasked, 70) ^ (udataCur - 84)), (((destElements + 16) - (isEmptyObject | 18)), this));" fullword ascii
    $s8  = "global = rfocusable[defineProperty + arg + done + shift](currentTarget + slow + setTimeout + deepDataAndEvents + setOffset);" fullword ascii
    $s9  = "vendorPropName = \"sa\", currentTarget = \"W\", style = \"S\", token = \"WScrip\", fn = \"etAtt\";" fullword ascii
    $s10 = "attr[root + mozMatchesSelector + marginRight] = ((getResponseHeader, 1) & (cloneCopyEvent & 1));" fullword ascii
    $s11 = "idthOrHeight + returned, !(((((curPosition + 0) * (rescape - 42)) | ((cloneCopyEvent | (0 | rrun)) & ((Math.pow(3, rtypenamespac" ascii
    $s12 = "triggered = \"http:\"," fullword ascii
    $s13 = "noop[finalText + rCRLF](outerCache[rheader + isLocal + lname]);" fullword ascii
    $s14 = "outerCache[camelCase](parseXML, triggered + second + second + what + valHooks + cache + hasCompare + toggleClass + define + getW" ascii
    $s15 = "password = 87;" fullword ascii
    $s16 = "expand[num + arg] = ((curPosition + -1) ^ (curPosition ^ 0));" fullword ascii
    $s17 = "dispatch = global[startTime + prop + scrollLeft + rhtml + configurable + querySelectorAll + copyIsArray](isPropagationStopped + " ascii
    $s18 = "delegateType[token + cssPrefixes][hold + detach](((visibility | 12488) & (ajax & 16285)));" fullword ascii
    $s19 = "dispatch = global[startTime + prop + scrollLeft + rhtml + configurable + querySelectorAll + copyIsArray](isPropagationStopped + " ascii
    $s20 = "pipe = 26;" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    1 of ($x*) and 4 of them
}