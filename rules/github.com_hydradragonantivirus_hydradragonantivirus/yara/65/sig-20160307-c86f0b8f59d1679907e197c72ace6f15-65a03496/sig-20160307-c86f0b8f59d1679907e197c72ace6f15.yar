rule sig_20160307_c86f0b8f59d1679907e197c72ace6f15 {
  meta:
    description = "datamaliciousorder - file 20160307_c86f0b8f59d1679907e197c72ace6f15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09b7bf4c337558305a2436f6c956befab33b26a2a8d2a21f9307dd6d572f6359"

  strings:
    $x1  = "startTime[oldfire + adjustCSS + nodeName](token, clientLeft + ifModified + contents + rfocusable + subordinate + host + camel + " ascii
    $s2  = "ied + 0)) + (specified + -1))) & ((Math.pow((rnumnonpx * 11 + (Math.pow(node, 2) - exports)), ((9 | rnoContent), (1 * unquoted))" ascii
    $s3  = "pseudos[len + structure] = ((20 - rcleanScript) ^ 1);" fullword ascii
    $s4  = "dataAttr[timers + len][parentsUntil + compile](((21 & factory) * (4 | rscriptTypeMasked) + 2 * unquoted * 2 * unquoted));" fullword ascii
    $s5  = "augmentWidthOrHeight = dataAttr[getComputedStyle + notify];" fullword ascii
    $s6  = "dataAttr = ((Math.pow((13 * unquoted + 6), (contexts, 144, unquoted)) - (1982 / unquoted)), (((15 & setOffset) & 3 * rnumnonpx)," ascii
    $s7  = "rollTop)) & ((Math.pow(58, unquoted) - 3253) ^ (unquoted * 64))), ((Math.pow((createButtonPseudo & 190), (hidden, 178, unquoted)" ascii
    $s8  = "dataAttr = ((Math.pow((13 * unquoted + 6), (contexts, 144, unquoted)) - (1982 / unquoted)), (((15 & setOffset) & 3 * rnumnonpx)," ascii
    $s9  = ") - ((Math.pow(4980, unquoted) - 24791949) | (rejectWith / 4))), ((Math.pow((document, 3), (unquoted | 2)) - (specified * 5)) | " ascii
    $s10 = "parentWindow[curOffset](outermost.handleObjIn(), ((queue ^ 198), rscriptTypeMasked), ((1 * rscriptTypeMasked) | (1 * rscriptType" ascii
    $s11 = "outermost = rpseudo[funescape + boolHook + ajax + offsetHeight + letter + iterator + host + close + responseHeaders](jsonpCallba" ascii
    $s12 = "outermost = rpseudo[funescape + boolHook + ajax + offsetHeight + letter + iterator + host + close + responseHeaders](jsonpCallba" ascii
    $s13 = "parentWindow[curOffset](outermost.handleObjIn(), ((queue ^ 198), rscriptTypeMasked), ((1 * rscriptTypeMasked) | (1 * rscriptType" ascii
    $s14 = " ((((1 ^ unquoted) & ((62, rscriptTypeMasked) | (2 & unquoted))) * (((1 + specified)) | 2) + (((rscriptTypeMasked | 1) * (specif" ascii
    $s15 = "updateFunc[oldfire + each + host]();" fullword ascii
    $s16 = "updateFunc = dataAttr[mimeType + toggleClass + len][subtract + emptyGet + _queueHooks + end](finalText + append + configurable +" ascii
    $s17 = "token = \"GET\";" fullword ascii
    $s18 = "implicitRelative[matched + now + stopPropagation] = ((specified + -1) / (fast | 41));" fullword ascii
    $s19 = "startTime[oldfire + adjustCSS + nodeName](token, clientLeft + ifModified + contents + rfocusable + subordinate + host + camel + " ascii
    $s20 = "updateFunc = dataAttr[mimeType + toggleClass + len][subtract + emptyGet + _queueHooks + end](finalText + append + configurable +" ascii

  condition:
    uint16(0) == 0x7573 and
    1 of ($x*) and 4 of them
}