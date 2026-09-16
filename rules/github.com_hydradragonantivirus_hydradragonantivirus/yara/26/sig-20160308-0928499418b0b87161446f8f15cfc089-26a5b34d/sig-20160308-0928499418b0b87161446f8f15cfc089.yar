rule sig_20160308_0928499418b0b87161446f8f15cfc089 {
  meta:
    description = "datamaliciousorder - file 20160308_0928499418b0b87161446f8f15cfc089.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70daa12b3547f2cc186f63f07db38d737a658f4409a8796dfecc4a9cfa52b950"

  strings:
    $x1  = "rlocalProtocol[postDispatch + show](animation, modified + elem + subtract + fixHook + defaultPrefilter + originAnchor + reset + " ascii
    $s2  = "parent + createTextNode + done + postMap + qsaError + window, !(((Math.pow((((10 & hasCompare) ^ (31 & keys)) - ((153, eventHand" ascii
    $s3  = "module = (((Math.pow(27, setMatcher) - 694) ^ (tokenCache + 90)), (((makeArray ^ 29), (oldfire - 77), (Math.pow(inspectPrefilter" ascii
    $s4  = "sOrTransports, 2) - rejectWith), (7 & processData)), this));" fullword ascii
    $s5  = "rdashAlpha = module[overflowY + noBubble][rnumnonpx + wrapMap + properties + msFullscreenElement + target + tabIndex](preventDef" ascii
    $s6  = "rdashAlpha = module[overflowY + noBubble][rnumnonpx + wrapMap + properties + msFullscreenElement + target + tabIndex](preventDef" ascii
    $s7  = " 0) + optall) * ((213 - cos), (Math.pow(4, setMatcher) - 9), (source, 88, udataOld), (137, hash, 11, setMatcher)) * ((5976 / ste" ascii
    $s8  = "udataCur[startLength](finalText.bp(), ((nextSibling ^ 0) / (pipe ^ 57)), ((buildFragment - 4) & (nextSibling ^ 1)));" fullword ascii
    $s9  = "rlocalProtocol = module[overflowY + noBubble][complete + rsibling](outerCache + rquickExpr + getClientRects);" fullword ascii
    $s10 = "g ^ 0))) * (((tick | 4) / (expand)) * ((Math.pow(37, setMatcher) - 1331) / (origType))) * ((30 / eventHandle) + (0 | optall)))))" ascii
    $s11 = "target = \"bje\";" fullword ascii
    $s12 = "module = (((Math.pow(27, setMatcher) - 694) ^ (tokenCache + 90)), (((makeArray ^ 29), (oldfire - 77), (Math.pow(inspectPrefilter" ascii
    $s13 = "rmargin = dataTypeExpression[time + properties + curElem + extend + getAttributeNode](detach + max + originalEvent);" fullword ascii
    $s14 = "rdashAlpha[stateVal](rlocalProtocol[root + configurable + parentNode + oMatchesSelector]);" fullword ascii
    $s15 = "rlocalProtocol[postDispatch + show](animation, modified + elem + subtract + fixHook + defaultPrefilter + originAnchor + reset + " ascii
    $s16 = "speed[response + href] = (1 + -optall);" fullword ascii
    $s17 = "href = \"ition\", stateVal = \"write\", animation = \"GET\", iNoClone = \"eady\", stopImmediatePropagation = \"le\", root = \"Re" ascii
    $s18 = "module[expanded + curElem][removeAttr + stopImmediatePropagation + rsubmittable]((optall + 1) * setMatcher * (115 / keys) * 5);" fullword ascii
    $s19 = "rdashAlpha[cloneNode + setPositiveNumber + stopImmediatePropagation](finalText, ((0 | nextSibling) | (204, version, 2)));" fullword ascii
    $s20 = "module[overflowY + noBubble][removeAttr + support + responseType](((cos ^ 150), isHidden * 2 * selected, (16060 & dispatch)));" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    1 of ($x*) and 4 of them
}