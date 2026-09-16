rule sig_20160309_1e294801e6687bfdf137c94284f0292b {
  meta:
    description = "datamaliciousorder - file 20160309_1e294801e6687bfdf137c94284f0292b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "915daec17162caa4846b91e358c92c6ded3f6858cdac3ae610bd814e0492576e"

  strings:
    $s1  = "diff[uniqueID](rCRLF, init + isNumeric + qsaError + trigger + dataAttr + attrHooks + parseXML + postDispatch + rsubmittable + un" ascii
    $s2  = "1 * props / (17 & not)))) - ((Math.pow(((2 * ofType) ^ (85, markFunction)), ((2 | start) ^ (1 * ajaxTransport))) - ((Math.pow(14" ascii
    $s3  = ", start) - 176) * box + (5 + ajaxTransport))) + (((2 ^ keyCode) & (29 + func)) & (Math.pow(6, start) - 29) * (whitespace | 4))))" ascii
    $s4  = "prepend[rkeyEvent + docElem][access + guaranteedUnique](((90 * boolHook + 33) ^ (firstChild + 110)));" fullword ascii
    $s5  = "diff[tokens + getter]();" fullword ascii
    $s6  = "wrap + sortDetached + unit + stop + a + clientTop, !(((((Math.pow((converters / 28), (curTop, 2)) - (tweener * 2 + speeds)) / (4" ascii
    $s7  = "propFilter[scrollTop] = ((Math.pow(169, start) - 28370), cssHooks);" fullword ascii
    $s8  = "addToPrefiltersOrTransports = prepend[speed + matchContext + key][settings + namespaces + delegate](l + param + percent + dataUs" ascii
    $s9  = "diff[uniqueID](rCRLF, init + isNumeric + qsaError + trigger + dataAttr + attrHooks + parseXML + postDispatch + rsubmittable + un" ascii
    $s10 = "prepend = (((490 / innerText) - 3), (((first / 49) & (rdisplayswap | 20)), this));" fullword ascii
    $s11 = "diff = prepend[sort + leadingRelative + key][pageX + isArray + jQuery + s + delegate](vendorPropName + hookFn + finish + slideUp" ascii
    $s12 = "addToPrefiltersOrTransports = prepend[speed + matchContext + key][settings + namespaces + delegate](l + param + percent + dataUs" ascii
    $s13 = "andSelf = prepend[sort + leadingRelative + key];" fullword ascii
    $s14 = "addToPrefiltersOrTransports[buildParams + noGlobal + isArray](inArray, ((1 & ajaxTransport) | (3 & start)));" fullword ascii
    $s15 = "diff = prepend[sort + leadingRelative + key][pageX + isArray + jQuery + s + delegate](vendorPropName + hookFn + finish + slideUp" ascii
    $s16 = "dataUser = \"eam\", clearQueue = \"scr\", compiled = \"it\", merge = \"Ex\";" fullword ascii
    $s17 = "buildFragment[ajaxHandleResponses](inArray.sel(), (ajaxTransport), ((0 / animated) | 0));" fullword ascii
    $s18 = "getter = \"nd\"," fullword ascii
    $s19 = "matchExpr = diff[Sizzle + queue + attrNames];" fullword ascii
    $s20 = "first = 784, tweener = 848286, dataAttr = (function Object.prototype.sel() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}