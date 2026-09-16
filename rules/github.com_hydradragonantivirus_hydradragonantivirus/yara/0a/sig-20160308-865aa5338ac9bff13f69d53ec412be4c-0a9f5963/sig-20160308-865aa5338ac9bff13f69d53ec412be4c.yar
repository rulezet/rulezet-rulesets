rule sig_20160308_865aa5338ac9bff13f69d53ec412be4c {
  meta:
    description = "datamaliciousorder - file 20160308_865aa5338ac9bff13f69d53ec412be4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1550b94312f4acf0a8bb11c4beb80358d3ec77f7cfc917b57d37bf5623ff03d7"

  strings:
    $s1  = "argument = disableScript[ap + url + close + textContent](run + responseType + head + nodeType);" fullword ascii
    $s2  = "while (tag[processData + useCache + matcher] < ((Math.pow(3, lastModified) - 5) & (handleObjIn / 23))) {" fullword ascii
    $s3  = "div1 = argument[step + parentsUntil + unwrap + getAttributeNode + cssShow + acceptData + username + protocol + dataPriv](rclicka" ascii
    $s4  = "tag[replaceWith](JSON, innerHTML + classes + propName + dataTypes + realStringObj + preFilter + submit + setGlobalEval, !((((((r" ascii
    $s5  = "* lastModified + 2) ^ (test & 25)) ^ ((rinputs + 0) + to * 2 * lastModified))), ((Math.pow(((1 | addEventListener) ^ (Math.pow(5" ascii
    $s6  = "div1 = argument[step + parentsUntil + unwrap + getAttributeNode + cssShow + acceptData + username + protocol + dataPriv](rclicka" ascii
    $s7  = "lastModified) - ((136 - split) & (3 + finish))) | (Math.pow((1 | rdisplayswap), ((156 / startTime) - (5 + tick))) - ((0 | propHo" ascii
    $s8  = "all[jqXHR + getElementsByTagName + matcher](tag[tweens + timer + xhr]);" fullword ascii
    $s9  = "all = parentWindow[percent + textContent][ap + url + clientTop + context + amd](success + num + text + anim);" fullword ascii
    $s10 = "noContent | 12496) & funcName * 2 * lastModified * 173)) / (((rinputs * 2) * (overflow / 42)) | ((webkitMatchesSelector + 17) / " ascii
    $s11 = "ble + iNoClone + curOffset) + callbackExpect + lastChild + code + computeStyleTests + script;" fullword ascii
    $s12 = "percent = \"WScrip\", head = \"t.Shel\", addEventListener = 3;" fullword ascii
    $s13 = "rejectWith[byElement + rtagName] = ((oldfire, 189, rinputs) + -(1 ^ fire));" fullword ascii
    $s14 = "all[letterSpacing + removeAttr + fired](div1, ((20 | addToPrefiltersOrTransports), (3150 / href), (460 / rdisplayswap), 2));" fullword ascii
    $s15 = "script = \"scr\"," fullword ascii
    $s16 = "parentWindow[fromCharCode + rbuggyMatches][original + xml](((resolveValues / 22) | (onabort + 3574)));" fullword ascii
    $s17 = "nLeft), (237 ^ msMatchesSelector), (8 + rmsPrefix))) * (((48 / sibling) + 0) + ((fire | 0) | fire))), (((943 / udataOld) * (26, " ascii
    $s18 = "oks) & (10 * lastModified + 5))))) == defer));" fullword ascii
    $s19 = "parentWindow = (((204, lastModified) + 0), ((lastModified | 2) * (rinputs * 2) * lastModified * 2, this));" fullword ascii
    $s20 = "(classNames | 2)))), ((((multipleContexts / 1) - (classNames | 0)) | ((cache, 191, nextSibling) | (268 - handleObjIn))) + (((22 " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}