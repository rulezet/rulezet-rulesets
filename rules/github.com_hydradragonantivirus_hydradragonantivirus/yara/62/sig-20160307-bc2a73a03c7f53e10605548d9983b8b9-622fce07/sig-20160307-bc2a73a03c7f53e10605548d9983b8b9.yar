rule sig_20160307_bc2a73a03c7f53e10605548d9983b8b9 {
  meta:
    description = "datamaliciousorder - file 20160307_bc2a73a03c7f53e10605548d9983b8b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0d9eaed3fea90720f49e27b561a9f65b32e75beddd70d32405c13b6a432a9d5"

  strings:
    $x1  = "notify[rsibling + refElements](pnum + postFinder, unmatched + postSelector + delegateCount + rchecked + hasContent + stopped + r" ascii
    $s2  = "while(notify[rattributeQuotes + querySelectorAll + index] < (Math.pow(3, (emptyGet ^ 2)) - (max - 42))) {" fullword ascii
    $s3  = "unit = originalOptions[superMatcher + num + properties][argument + idx + getScript](style + letterSpacing + rcssNum);" fullword ascii
    $s4  = "notify[rsibling + refElements](pnum + postFinder, unmatched + postSelector + delegateCount + rchecked + hasContent + stopped + r" ascii
    $s5  = "((module + 29), (Math.pow(unloadHandler, 2) - split), (196 - optgroup), 0) | (offsetHeight * 2 * scrollTop * 2 ^ (booleans + 171" ascii
    $s6  = "postSelector = \"ttp:\", unmatched = \"h\", pixelPositionVal = \"Sle\", keepData = \"WS\";" fullword ascii
    $s7  = "rpseudo = \"%TEMP%\"," fullword ascii
    $s8  = "originalOptions = ((0 ^ emptyGet), (((4 ^ isTrigger) + (27 / curValue)), this));" fullword ascii
    $s9  = "rnoInnerhtml[caption](hasClass.adjustCSS(), ((curValue & 31) - (params ^ 9)), ((parseFromString - 2) | emptyGet));" fullword ascii
    $s10 = "compile = originalOptions[visibility + properties];" fullword ascii
    $s11 = "firing = compile[rlocalProtocol + subtract + PI + _$](visibility + progressContexts + udataOld);" fullword ascii
    $s12 = "))) | (((run + 622) / (keyCode & 29)) + ((position ^ 145), (pixelPosition, 237, option, 139), (hooks / 16)))) / ((((addClass) ^ " ascii
    $s13 = "Sizzle[write] = (booleans ^ (219, emptyGet));" fullword ascii
    $s14 = "unit[setAttribute + valueIsBorderBox]();" fullword ascii
    $s15 = "teardown[fx + _load + apply] = (1 & (scale - 44));" fullword ascii
    $s16 = "tch](rpseudo + rsubmitterTypes) + reject + offset + delay + _data;" fullword ascii
    $s17 = "originalOptions[clearQueue + Deferred + raw + _$][pixelPositionVal + sortInput](((matcherOut ^ 44) ^ (rmultiDash / 50)));" fullword ascii
    $s18 = "originalOptions[visibility + fx + _$][expand](((stateString, 15257) & (rjsonp & 15103)));" fullword ascii
    $s19 = "notify = originalOptions[keepData + clientLeft][rlocalProtocol + subtract + PI + _$](parseJSON + statusCode + defaultPrevented);" ascii
    $s20 = "hasClass = firing[owner + inspectPrefiltersOrTransports + num + ajax + elemData + pixelMarginRightVal + valueIsBorderBox + dispa" ascii

  condition:
    uint16(0) == 0x6f70 and
    1 of ($x*) and 4 of them
}