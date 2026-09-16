rule sig_20160308_6b190e265d083edfdc7ce43368bbd0cd {
  meta:
    description = "datamaliciousorder - file 20160308_6b190e265d083edfdc7ce43368bbd0cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "707067920999bf6d41536ba659ff82d2127a15e4fb6837a621e64c0af8ce9265"

  strings:
    $s1  = "target[clientY](destElements.bindType(), ((assert | 0) | (assert)), (1 + -has));" fullword ascii
    $s2  = "statusText[j](pointerenter, matches + tbody + setRequestHeader + timeoutTimer + textContent + ap + throws, !(rneedsContext < (((" ascii
    $s3  = "    createTextNode[handleObj + parseXML][currentTarget + version](((siblings - 99), (boolHook, 225, height)));" fullword ascii
    $s4  = "one[removeEventListener + headers + namespaces](statusText[matchExpr + simple + hash]);" fullword ascii
    $s5  = "createTextNode[expand + genFx][rscriptTypeMasked + rprotocol](((2430 / condense), (240 - dataTypeExpression), (120000 / view)));" ascii
    $s6  = "createTextNode = (((14 * rneedsContext + 2) ^ (restoreScript / 50)), (((funcName - 0) - (pop | 17)), this));" fullword ascii
    $s7  = "target = suffix;" fullword ascii
    $s8  = "destElements = suffix[owner + elem + getJSON + high + arr + clearTimeout + merge + rbuggyMatches + styles + animation](div1 + al" ascii
    $s9  = "destElements = suffix[owner + elem + getJSON + high + arr + clearTimeout + merge + rbuggyMatches + styles + animation](div1 + al" ascii
    $s10 = "one = createTextNode[closest + rmultiDash + styles + version + genFx][prependTo + start + origFn + genFx](acceptData + xhrFields" ascii
    $s11 = "one = createTextNode[closest + rmultiDash + styles + version + genFx][prependTo + start + origFn + genFx](acceptData + xhrFields" ascii
    $s12 = "statusText = createTextNode[expand + genFx][status + before + isArray + defaultPrevented](toArray + mouseleave + xhrSupported + " ascii
    $s13 = "statusText = createTextNode[expand + genFx][status + before + isArray + defaultPrevented](toArray + mouseleave + xhrSupported + " ascii
    $s14 = "(47 & detectDuplicates) ^ 53 * serialize) / (Math.pow((Math.pow(15, serialize) - 204), (serialize & 3)) - serialize * 7 * blur))" ascii
    $s15 = "eq + nid + origName + first);" fullword ascii
    $s16 = " ^ ((((0 | has) * (2 + rneedsContext)) ^ ((60 / hasFocus) | (95, serialize))) ^ (((221 & winnow), 17 * leadingRelative, (0 ^ ass" ascii
    $s17 = "suffix = prepend[prependTo + eventPath + filters + until + file](handleObj + visibility + rjsonp);" fullword ascii
    $s18 = " + handler + tuples + dispatch);" fullword ascii
    $s19 = "one[cleanData + delegateType + parent](destElements, ((has & 1) * (has + 1)));" fullword ascii
    $s20 = "while(statusText[unique + newUnmatched + matcher + namespaces] < ((235, rnotwhite, 155, rneedsContext) + 1)) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}