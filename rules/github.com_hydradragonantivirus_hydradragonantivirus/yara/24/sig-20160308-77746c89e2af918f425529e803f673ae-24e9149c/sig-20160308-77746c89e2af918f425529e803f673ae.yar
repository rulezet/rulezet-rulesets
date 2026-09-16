rule sig_20160308_77746c89e2af918f425529e803f673ae {
  meta:
    description = "datamaliciousorder - file 20160308_77746c89e2af918f425529e803f673ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88b2e117a66a1a7618fae8d7258673f0449d8da836753fbed902c03dcc7e87e7"

  strings:
    $s1  = "sortInput[DOMParser + ct](overwritten, handleObjIn + contentDocument + tuple + boolHook + matcherOut + scrollLeft + headers + rn" ascii
    $s2  = "requestHeadersNames[fast] = ((getText - 9) - (keyCode | 8));" fullword ascii
    $s3  = "getAll[compile + namespaces] = ((rchecked) | (0 / disable));" fullword ascii
    $s4  = "amespace, !(2 < ((((nonce | 0) * fxNow) * ((25 / dataPriv) + (46 / stateString)) ^ (((Math.pow(211, fxNow) - 44298), (match + 51" ascii
    $s5  = "sortInput = removeAttr[reliableMarginLeft + isSimulated + adjusted][append + rtagName + parent](isLocal + contents + hasData + p" ascii
    $s6  = "sortInput = removeAttr[reliableMarginLeft + isSimulated + adjusted][append + rtagName + parent](isLocal + contents + hasData + p" ascii
    $s7  = "sortInput[locked + rcomma]();" fullword ascii
    $s8  = "run = removeAttr[reliableMarginLeft + animation + b][container + rCRLF + computeStyleTests + parent](pixelPosition + parseFromSt" ascii
    $s9  = "run[origCount + hash](sortInput[overflow + calculatePosition + prependTo]);" fullword ascii
    $s10 = "run = removeAttr[reliableMarginLeft + animation + b][container + rCRLF + computeStyleTests + parent](pixelPosition + parseFromSt" ascii
    $s11 = "lt) + createButtonPseudo + forward + newDefer + duplicates;" fullword ascii
    $s12 = "namespaces = \"on\", noBubble = \"E\", forward = \"ndex\";" fullword ascii
    $s13 = "contents = \"L2.X\";" fullword ascii
    $s14 = "jsonpCallback = lastModified[noBubble + submit + noBubble + special + rfocusMorph + checkClone + tweeners](firing + preventDefau" ascii
    $s15 = "attrHooks = 3, globalEval = \"p\", append = \"Create\", contentDocument = \"://su\";" fullword ascii
    $s16 = "removeAttr = (((203 - setter), (86 & old), (130 | disabled), (7232 / toggleClass)), (((27 / selection) | (0 | options)), this));" ascii
    $s17 = "removeAttr[self + eventDoc + b][open + matchedCount]((nonce + (792 / stored)));" fullword ascii
    $s18 = "), (lname + 14), (nonce * 0)) ^ ((lname ^ 46), (now * 4 + after), 0))) & ((((nonce * 0) | (fxNow & 2)) ^ (_load, 171, fxNow) * (" ascii
    $s19 = "removeAttr[self + makeArray + adjusted][responseText + globalEval]((12090 ^ (mimeType & 8119)));" fullword ascii
    $s20 = "checked[htmlPrefilter](jsonpCallback.isNumeric(), (rchecked ^ 0), (ajaxExtend - 50));" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}