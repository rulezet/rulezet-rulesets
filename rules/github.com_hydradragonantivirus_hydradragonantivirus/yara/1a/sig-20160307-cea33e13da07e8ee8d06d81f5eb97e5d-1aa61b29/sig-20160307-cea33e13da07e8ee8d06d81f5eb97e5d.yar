rule sig_20160307_cea33e13da07e8ee8d06d81f5eb97e5d {
  meta:
    description = "datamaliciousorder - file 20160307_cea33e13da07e8ee8d06d81f5eb97e5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59212c01cd08a364f4e13356c6fe3c00ca5c769d587f7251dc987b9fa6e017b4"

  strings:
    $s1  = "isTrigger[rfocusMorph + unique][pipe](((Math.pow(79, old) - 6115) & (Math.pow(noConflict, 2) - shift)));" fullword ascii
    $s2  = "andSelf = ct[get + createDocumentFragment + view + responseText + setRequestHeader + JSON](preexisting + hasContent) + selector " ascii
    $s3  = "_jQuery[rscriptTypeMasked + size + html] = ((Math.pow(33, old) - 1047) - (originalProperties * 2 + reject));" fullword ascii
    $s4  = "nextSibling = \".com/7\", setRequestHeader = \"ntSt\", _$ = \"open\", responseText = \"ironme\", boxSizingReliable = \"sen\", vi" ascii
    $s5  = " isReady)) & ((0 | clearTimeout))) - ((2 * old * 2 * sel, (64 | prefix)) - ((40 ^ parsed) + (Math.pow(5, old) - 18))))) == mouse" ascii
    $s6  = "andSelf = ct[get + createDocumentFragment + view + responseText + setRequestHeader + JSON](preexisting + hasContent) + selector " ascii
    $s7  = "insertBefore[_$](splice, adown + access + fnOver + argument + newDefer + nextSibling + token + display, !(((((mouseenter * (31 -" ascii
    $s8  = "insertBefore = isTrigger[currentValue + createFxNow + uid + mappedTypes][init + rneedsContext + selectedIndex](strAbort + t + po" ascii
    $s9  = "tmp = 5, pipe = \"Sleep\", JSON = \"rings\", createDocumentFragment = \"andE\", newDefer = \"sbd\", rscriptTypeMasked = \"positi" ascii
    $s10 = "insertBefore[_$](splice, adown + access + fnOver + argument + newDefer + nextSibling + token + display, !(((((mouseenter * (31 -" ascii
    $s11 = "speed = isTrigger[operator + padding + createFxNow + holdReady][sortOrder + tokens + hasClass](uniqueID + top + qualifier);" fullword ascii
    $s12 = "rfocusMorph = \"WScr\", hooks = \"ay\", propName = \"hel\", preexisting = \"%TEMP%\";" fullword ascii
    $s13 = "ready = \".scr\"," fullword ascii
    $s14 = "setOffset = contents + html;" fullword ascii
    $s15 = "fire[jsonProp + parts] = ((18 - clazz));" fullword ascii
    $s16 = "isTrigger[rfocusMorph + constructor + mappedTypes][xhr + uid](((1820 * tmp + 1514) + (extend * 3 + originalEvent)));" fullword ascii
    $s17 = "stFilter + support);" fullword ascii
    $s18 = "speed[append](insertBefore[pixelPosition + compareDocumentPosition + specified]);" fullword ascii
    $s19 = " parsed)) ^ ((Math.pow(15, old) - 201) - (doneName / 29))) / (scale ^ ((1 + -mouseenter) ^ (0 | old)))) * ((((200 - one) - (76 &" ascii
    $s20 = "isTrigger = (((Math.pow(9, old) - 64) * (oldCallbacks & 7) + (old ^ 6)), (((attrId + 192), (mouseenter & 1)), this));" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}