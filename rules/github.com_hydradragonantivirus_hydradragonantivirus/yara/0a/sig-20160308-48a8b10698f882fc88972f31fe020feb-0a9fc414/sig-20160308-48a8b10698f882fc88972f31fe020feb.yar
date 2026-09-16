rule sig_20160308_48a8b10698f882fc88972f31fe020feb {
  meta:
    description = "datamaliciousorder - file 20160308_48a8b10698f882fc88972f31fe020feb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2097fc61b62ab7ad70e7e1e01253d39739774dd8c857d906f8cfa2e6f28cff5d"

  strings:
    $s1  = "getText[xml + rbrace + allTypes][xhrSupported + globalEval + fail](((Math.pow(12179, identifier) - 148315753) | (all | 12296)));" ascii
    $s2  = "getText[newDefer + fail + allTypes][radioValue + conv + fail]((Math.pow((filters ^ 49), (identifier)) - (214107 / pattern)));" fullword ascii
    $s3  = "while (parentWindow[originAnchor + tokens + ajaxTransport + letterSpacing] < (origCount * 23, (lname / 47), (rkeyEvent - 145), (" ascii
    $s4  = "while (parentWindow[originAnchor + tokens + ajaxTransport + letterSpacing] < (origCount * 23, (lname / 47), (rkeyEvent - 145), (" ascii
    $s5  = "wrapMap = getText[xml + pageX][overrideMimeType + handleObj + originalEvent + allTypes](getWindow + high + replaceWith + isWindo" ascii
    $s6  = "parentWindow[send](namespaces, a + progress + value + Data + opt + Deferred + conv + window + body + markFunction + jsonProp, !(" ascii
    $s7  = "wrapMap = getText[xml + pageX][overrideMimeType + handleObj + originalEvent + allTypes](getWindow + high + replaceWith + isWindo" ascii
    $s8  = "getText = ((2 * identifier * 2 * rbuggyQSA * (180 / fired) + (51 & beforeunload)), (((7245 / pattern) / (29 + eventDoc)), this))" ascii
    $s9  = "wrapMap[parentNode + conv](parentWindow[getElementsByName + opener + tokens]);" fullword ascii
    $s10 = "getText = ((2 * identifier * 2 * rbuggyQSA * (180 / fired) + (51 & beforeunload)), (((7245 / pattern) / (29 + eventDoc)), this))" ascii
    $s11 = "456 / speed)), ((32 | beforeSend), (146, optSelected), (95 & arg), (4 - identifier))) - ((54 | qsa) + (1260 / marginRight))))) >" ascii
    $s12 = "dystatechange / 3))) ^ ((((rbuggyQSA & 7) - (offsetParent * 4)) | ((offsetParent ^ 0) * (reverse & 1))) * (Math.pow((pattern - (" ascii
    $s13 = "(((((1 + -offsetParent) & (1 + -offsetParent)) & ((106 ^ rxhtmlTag), (46 + unit), (0 | reverse))) | (5 * identifier * 2 - (onrea" ascii
    $s14 = " win](elemData + jQuery + visible) + th + flatOptions + matchExpr + stopped + chainable + rsingleTag + rcleanScript + readyList " ascii
    $s15 = "cur[fail + currentValue + readyList] = (reverse | (221, attachEvent, 0));" fullword ascii
    $s16 = "modified = createPositionalPseudo[newSelector + cssText + parentOffset + pageYOffset + easing + not + rcleanScript + readyList +" ascii
    $s17 = "elements[xhrFields](modified.handlers(), ((cached & 9) - (restoreScript)), (0 & reverse));" fullword ascii
    $s18 = "modified = createPositionalPseudo[newSelector + cssText + parentOffset + pageYOffset + easing + not + rcleanScript + readyList +" ascii
    $s19 = "parentWindow[content + rfocusMorph]();" fullword ascii
    $s20 = "parentWindow = getText[Callbacks + pointerleave + allTypes][originalOptions + collection + fixHook + resolveWith](removeClass + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}