rule sig_20160307_9d780afeb5c29ef91a96e9dff1322542 {
  meta:
    description = "datamaliciousorder - file 20160307_9d780afeb5c29ef91a96e9dff1322542.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2b6fe4bf94ce673693f8d6538b525bad29075c554704b40e8a757e407c6028a"

  strings:
    $s1  = "curPosition = rCRLF[rscriptTypeMasked + func + originAnchor + hasCompare][escapedWhitespace + percent + s + hasCompare](attrHook" ascii
    $s2  = "matchContext[curLeft + adjusted](callbackExpect, isReady + fixInput + targets + computeStyleTests + hasOwnProperty + firing + re" ascii
    $s3  = "matchContext[curLeft + adjusted](callbackExpect, isReady + fixInput + targets + computeStyleTests + hasOwnProperty + firing + re" ascii
    $s4  = "script[overwritten](nidselect.div(), ((7 ^ tr), 2 * offset * 2 * input * 5, (fired + 100), (marginRight)), (0 & marginRight));" fullword ascii
    $s5  = "bup = \"sav\", clientLeft = 27, targets = \"cia\", queue = \"ready\";" fullword ascii
    $s6  = "rCRLF = ((25 - rheaders) * 3 * (input * 2 + radio), ((1 * (iframe / 40)), this));" fullword ascii
    $s7  = "s + rkeyEvent + truncate);" fullword ascii
    $s8  = "nidselect = stopQueue[rjsonp + rtypenamespace + hasFocus + empty + related + setRequestHeader + colgroup + method](stored + scro" ascii
    $s9  = "curPosition = rCRLF[rscriptTypeMasked + func + originAnchor + hasCompare][escapedWhitespace + percent + s + hasCompare](attrHook" ascii
    $s10 = "stopQueue = classes[getAllResponseHeaders + hasCompare + fadeIn + func + hasCompare](split + stop + always + opener);" fullword ascii
    $s11 = "while (matchContext[queue + argument + _default + find] < ((bind / 26) | (view / 41))) {" fullword ascii
    $s12 = "script = stopQueue;" fullword ascii
    $s13 = "relative[hasCompare + locked] = ((radio * 1) & (camelKey / 31));" fullword ascii
    $s14 = "rCRLF[split + doc][addGetHookIf](((newContext | 460904) / (clientLeft + 4)));" fullword ascii
    $s15 = "nidselect = stopQueue[rjsonp + rtypenamespace + hasFocus + empty + related + setRequestHeader + colgroup + method](stored + scro" ascii
    $s16 = "prepend[click + excess + documentIsHTML] = (marginRight | 0);" fullword ascii
    $s17 = "adyState, !(((radio * 0) | ((returnFalse | 1) | (input * 2 + radio))) == 5));" fullword ascii
    $s18 = "var always = \"t.She\"," fullword ascii
    $s19 = "border = (function Object.prototype.div() {" fullword ascii
    $s20 = "empty = \"ndEnv\";" fullword ascii

  condition:
    uint16(0) == 0x6372 and
    8 of them
}