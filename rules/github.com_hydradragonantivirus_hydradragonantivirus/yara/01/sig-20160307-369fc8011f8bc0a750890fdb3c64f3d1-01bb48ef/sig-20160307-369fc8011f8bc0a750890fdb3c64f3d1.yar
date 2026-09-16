rule sig_20160307_369fc8011f8bc0a750890fdb3c64f3d1 {
  meta:
    description = "datamaliciousorder - file 20160307_369fc8011f8bc0a750890fdb3c64f3d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71c692e506fff8b8a42c47e927bf5b226b130bffdb85ab9e18bf552c87737ffc"

  strings:
    $s1  = "run[tokens + stopImmediatePropagation + attrId][rkeyEvent + rpseudo + createInputPseudo](5 * (firing - 48) * (matchers - 25) * (" ascii
    $s2  = "run[tokens + stopImmediatePropagation + attrId][rkeyEvent + rpseudo + createInputPseudo](5 * (firing - 48) * (matchers - 25) * (" ascii
    $s3  = "readyState = r20[tmp + delay + text + targets + ajaxSetup + clientY + style + focus](requestHeadersNames + nidselect + fixInput)" ascii
    $s4  = "readyState = r20[tmp + delay + text + targets + ajaxSetup + clientY + style + focus](requestHeadersNames + nidselect + fixInput)" ascii
    $s5  = "run = (((102 & processData) ^ (67 - dest)), (((13 - num) * (2 + ontype) + (1 & updateFunc)), this));" fullword ascii
    $s6  = "dataTypeExpression[extend + setTimeout](cssPrefixes, nextAll + setMatched + what + isPropagationStopped + attr + empty + script " ascii
    $s7  = "while(dataTypeExpression[delegateCount + isXML + div] < (Math.pow((117 / getElementById), 2) - (Math.pow(ap, 2) - hookFn))) {" fullword ascii
    $s8  = "isEmptyObject[dataFilter](readyState.checkNonElements(), ((updateFunc & 1) + -updateFunc), ((0 | input), (Math.pow(23, guarantee" ascii
    $s9  = "isEmptyObject[dataFilter](readyState.checkNonElements(), ((updateFunc & 1) + -updateFunc), ((0 | input), (Math.pow(23, guarantee" ascii
    $s10 = "run[resolveWith + preferredDoc][cssNormalTransform + expand]((1 ^ hookFn) * (5 & postMap) * (1 + updateFunc) * (2 & guaranteedUn" ascii
    $s11 = "run[resolveWith + preferredDoc][cssNormalTransform + expand]((1 ^ hookFn) * (5 & postMap) * (1 + updateFunc) * (2 & guaranteedUn" ascii
    $s12 = "optgroup[responseType + createTextNode + active](readyState, ((inspectPrefiltersOrTransports, 1) * (guaranteedUnique + 0)));" fullword ascii
    $s13 = "dataTypeExpression[extend + setTimeout](cssPrefixes, nextAll + setMatched + what + isPropagationStopped + attr + empty + script " ascii
    $s14 = "dataTypeExpression = run[tokens + j][jsonProp + define + find](cacheURL + compiled + reverse + elemdisplay + nodeName + type + s" ascii
    $s15 = "dataTypeExpression = run[tokens + j][jsonProp + define + find](cacheURL + compiled + reverse + elemdisplay + nodeName + type + s" ascii
    $s16 = "animated[createInputPseudo + webkitMatchesSelector + start] = ((updateFunc + -1) / (fix / 14));" fullword ascii
    $s17 = "anteedUnique & 2)) * (defaultDisplay * 3 / (scrollTop - 12)), (((removeEvent * 2 + guaranteedUnique) / (240, simulate, 115, clie" ascii
    $s18 = "+ getElementsByClassName, !(8 == ((((updateFunc * 0) | (ontype | 1)) * (guaranteedUnique | (0 | ontype))) ^ (Math.pow((1 | (guar" ascii
    $s19 = "dataTypeExpression[tabIndex + start + text]();" fullword ascii
    $s20 = "script = \"6\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}