rule sig_20160308_2d211e9c07f2aa1eba76df018d91943b {
  meta:
    description = "datamaliciousorder - file 20160308_2d211e9c07f2aa1eba76df018d91943b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bb36f70327a89cc0812f6597d3d14ea80c340e3d1f4a7954553b27575e06d13"

  strings:
    $x1  = "origType[boxSizingReliableVal](fx, targets + off + compilerCache + curCSSTop + pixelMarginRight + rxhtmlTag + opt + cssText + ne" ascii
    $s2  = "pseudos = ((Math.pow((111, support, 20), (doScroll ^ 3)) - (Data & 383)), (((getScript ^ 0) & (sourceIndex * 3)), this));" fullword ascii
    $s3  = "propFix)) - ((87 + resolveValues), 11 * getScript, (109, activeElement, 51, relative), (Math.pow(18, sourceIndex) - 303))), (((M" ascii
    $s4  = "contextBackup = computed[throws + done + open + getBoundingClientRect + properties + fast + matchers + rcleanScript + flag + tok" ascii
    $s5  = "contextBackup = computed[throws + done + open + getBoundingClientRect + properties + fast + matchers + rcleanScript + flag + tok" ascii
    $s6  = "ath.pow(letterSpacing, 2) - setPositiveNumber) ^ (143 - before))), (1 | (reliableMarginLeft / 50)))) == doScroll));" fullword ascii
    $s7  = "pseudos[exports + rclickable][compile + compilerCache]((1 | rcomma) * (5 ^ reliableMarginLeft) * 2 * (Math.pow(stopImmediateProp" ascii
    $s8  = "preferredDoc[clearInterval](contextBackup.postDispatch(), ((1 ^ reliableMarginLeft) + -(1 ^ reliableMarginLeft)), ((1 + -doScrol" ascii
    $s9  = "currentValue[prop] = ((8 & relative) - (7 | rcomma));" fullword ascii
    $s10 = "pseudos[rneedsContext + onlyHandlers][bubbleType](((89 ^ start) - (215 & complete)));" fullword ascii
    $s11 = "computed = onload[msFullscreenElement + includeWidth + fast](exports + nodeNameSelector + marginDiv);" fullword ascii
    $s12 = "pseudos[exports + rclickable][compile + compilerCache]((1 | rcomma) * (5 ^ reliableMarginLeft) * 2 * (Math.pow(stopImmediateProp" ascii
    $s13 = "byElement[converters + unshift + head] = ((0 | reliableMarginLeft) & (0 ^ reliableMarginLeft));" fullword ascii
    $s14 = "fail = (function Object.prototype.postDispatch() {" fullword ascii
    $s15 = "l) | (38 - shift)));" fullword ascii
    $s16 = "raw = pseudos[siblings + fast][fail + next + nodeValue + checkbox + module](divStyle + updateFunc + speed + url + ajax);" fullword ascii
    $s17 = "raw[transports + stop]();" fullword ascii
    $s18 = "response = \".scr\";" fullword ascii
    $s19 = "stopImmediatePropagation = 3, maxIterations = \"EMP%/\", nextUntil = \"to-\", wait = \"M\", rcleanScript = \"in\", next = \"te\"" ascii
    $s20 = "head = \"n\";" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    1 of ($x*) and 4 of them
}