rule sig_20160308_fe86887281df117db70f92df453a6bc4 {
  meta:
    description = "datamaliciousorder - file 20160308_fe86887281df117db70f92df453a6bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "400a5ed2e00baf90919d250e0c2e95199ef3c00b429ddfe06952ecd9d8e79708"

  strings:
    $x1  = "while (computeStyleTests[rnoContent + boolHook] < (Math.pow((3 + curLeft), (2 | appendChild)) - (2 ^ processData))) {" fullword ascii
    $s2  = "computeStyleTests = argument[password + result + maxWidth + curElem][chainable + structure + nodeType + reset + curElem](nextUnt" ascii
    $s3  = "argument = (17 * (processData), ((3 | (bup + 10)), this));" fullword ascii
    $s4  = "checkClone[tokenCache + result + cssText](computeStyleTests[whitespace + rsibling + dirrunsUnique + getResponseHeader + condense" ascii
    $s5  = "checkClone[tokenCache + result + cssText](computeStyleTests[whitespace + rsibling + dirrunsUnique + getResponseHeader + condense" ascii
    $s6  = "argument[tweens + flatOptions][original + rnative]((7 * firing * (Math.pow(3, appendChild) - 5) + (w - 12)));" fullword ascii
    $s7  = " udataOld), (2 + appendChild)) / (227, xml, (76 | safeActiveElement), (Math.pow(3, appendChild) - 5))) ^ ((lastChild, 193, until" ascii
    $s8  = "computeStyleTests = argument[password + result + maxWidth + curElem][chainable + structure + nodeType + reset + curElem](nextUnt" ascii
    $s9  = "ring)), (((5 * firing + 2) - (test + 11)) * ((orig - 29) * (bup * 2)))) | ((((traditional & 127), firing * 17, (Math.pow(l, 2) -" ascii
    $s10 = "matcherFromTokens[type] = (test - 4);" fullword ascii
    $s11 = "useCache = querySelectorAll[one + acceptData + pos](manipulationTarget + options + rinputs + then);" fullword ascii
    $s12 = "write = \"am\", manipulationTarget = \"WS\";" fullword ascii
    $s13 = "offsetHeight[prevObject + allTypes + button + defaultDisplay] = (curLeft | (0 / scriptCharset));" fullword ascii
    $s14 = "computeStyleTests[hold](noCloneChecked, not + preFilter + isSuccess + related + to + initial + attrId + className + newDefer + o" ascii
    $s15 = " + (2 * matchers - (55 ^ finalDataType))), (((5 * firing) & (7 ^ checkbox)) * (6 * appendChild + 1) + (bup | 2) * (done, 119, fi" ascii
    $s16 = "ntype, !(((((responseContainer ^ (29 - curLeft)) + (6 & (test & 5))), (((num + 16) | (pixelMarginRightVal * 3 + documentIsHTML))" ascii
    $s17 = "var password = \"WSc\"," fullword ascii
    $s18 = "_queueHooks[v](wrapMap.addHandle(), ((25 - curCSSLeft) * 0), ((swing / 4) + -(curLeft | 1)));" fullword ascii
    $s19 = "checkClone = argument[tweens + allTypes + start][matches + mozMatchesSelector + rootjQuery](dest + node + attachEvent + write);" fullword ascii
    $s20 = "querySelectorAll = argument[appendTo + start];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}