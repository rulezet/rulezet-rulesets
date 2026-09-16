rule sig_20160307_cb329349c6ca14c8384862c7931a3ad7 {
  meta:
    description = "datamaliciousorder - file 20160307_cb329349c6ca14c8384862c7931a3ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f08856599fab752a6483722725c8c5b0e68e683a1e9103d1fa80144a5edff05"

  strings:
    $s1  = "testContext[curPosition](responseFields, winnow + headers + position + username + cached + param + uniqueID + contentType + rfxt" ascii
    $s2  = "eventPath = completeDeferred[ofType + fadeOut + expand + getPropertyValue + marginDiv + fadeOut](bindType + condense + rrun + ni" ascii
    $s3  = "eventPath = completeDeferred[ofType + fadeOut + expand + getPropertyValue + marginDiv + fadeOut](bindType + condense + rrun + ni" ascii
    $s4  = ") | (Math.pow(timers, 2) - readyState)) - (113, addHandle * 2 * addHandle * 19, (attaches * 3 + timers), (12 * name + 2))) * (((" ascii
    $s5  = "testContext[curPosition](responseFields, winnow + headers + position + username + cached + param + uniqueID + contentType + rfxt" ascii
    $s6  = "$ = matchContext[getBoundingClientRect + letterSpacing + rheaders + overflowY][createButtonPseudo + compare + uniqueSort + fadeO" ascii
    $s7  = "testContext = matchContext[bindType + rheaders + overflowY][allTypes + prop + j](minWidth + offset + matcherOut + cssProps);" fullword ascii
    $s8  = "$ = matchContext[getBoundingClientRect + letterSpacing + rheaders + overflowY][createButtonPseudo + compare + uniqueSort + fadeO" ascii
    $s9  = "winnow = \"http:\"," fullword ascii
    $s10 = "getAttributeNode[getStyles + oldfire + pointerleave + related] = (refElements, 105, curCSSLeft);" fullword ascii
    $s11 = "subordinate[currentTime](removeAttr.register(), (17 * addHandle - 17 * addHandle), ((0 / has) ^ (1 * curCSSLeft)));" fullword ascii
    $s12 = "while(testContext[returnFalse + unbind + expand] < ((addHandle * 2) & (access / 39))) {" fullword ascii
    $s13 = "testContext[interval + related + dataUser]();" fullword ascii
    $s14 = "hover = \"%TEMP\"," fullword ascii
    $s15 = "completeDeferred = matchContext[bindType + condense + fadeOut];" fullword ascii
    $s16 = "handleObj = 1, dataShow = \"ite\", rrun = \"t.Shel\", rinputs = \"eam\", configurable = \"nc\", special = 48;" fullword ascii
    $s17 = "removeAttr = eventPath[funescape + send + elemdisplay + optSelected + maxWidth + transport + pseudos](hover + mapped) + opt + co" ascii
    $s18 = "rmsPrefix = \"Respon\", related = \"n\", getPropertyValue = \"O\";" fullword ascii
    $s19 = "ut](add + success + rinputs);" fullword ascii
    $s20 = "matchContext[cors + overflowY][fix](((curCSSLeft / 29) | (curOffset * 11 + height)));" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}