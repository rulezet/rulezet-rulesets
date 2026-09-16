rule sig_20160307_526dd6e5131e25fa7ad91217a04ece0f {
  meta:
    description = "datamaliciousorder - file 20160307_526dd6e5131e25fa7ad91217a04ece0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01400dc017bab555f054317da539e04fa083b41c20338eae5e99be88b00bf9f8"

  strings:
    $x1  = "curElem[hover + visibility](progress, attrs + currentValue + subordinate + node + setFilters + elementMatcher + rmargin + disabl" ascii
    $s2  = "eScript + elemData + global + setup, !((((((speeds & 1) & (speeds + 0)) * (Math.pow((qsaError, 3), (beforeSend, 79, content)) - " ascii
    $s3  = "access[value + hash + delegateCount][push_native]((speeds * 2) * (content ^ 0) * (cur | 5) * (sibling - 16));" fullword ascii
    $s4  = "(0 | fontWeight))))) == (((1 + (guid - 35)) | (((content & 3) | (buildParams / 13)) & ((Math.pow(deep, 2) - origCount), (17 - cu" ascii
    $s5  = "rpseudo = isPropagationStopped[expanded + responseText + send + wait + fixHook + isSuccess + targets](createTextNode + getProper" ascii
    $s6  = "curElem = access[when + delegateCount][old + offsetParent + rbuggyMatches + s + mouseHooks](domManip + target + rnative + anim +" ascii
    $s7  = "access = (((12 | matcherIn) + (18 | setRequestHeader)), (((3 * content + 1) & (returnValue ^ 0)), this));" fullword ascii
    $s8  = "curElem = access[when + delegateCount][old + offsetParent + rbuggyMatches + s + mouseHooks](domManip + target + rnative + anim +" ascii
    $s9  = "while(curElem[acceptData + rmsPrefix + bool] < (Math.pow((2 ^ speeds), 2) - (setMatcher - 43))) {" fullword ascii
    $s10 = "rpseudo = isPropagationStopped[expanded + responseText + send + wait + fixHook + isSuccess + targets](createTextNode + getProper" ascii
    $s11 = "subtract[tmp](rpseudo.parseJSON(), ((1 | speeds) & (0 | cur)), ((0 ^ cur) / 2 * ridentifier * 2));" fullword ascii
    $s12 = "target = \"XM\";" fullword ascii
    $s13 = "disabled[callbackContext + responseHeadersString + parseHTML + settings](rpseudo, content);" fullword ascii
    $s14 = "getStyles = access[multipleContexts + mimeType];" fullword ascii
    $s15 = "detach[destElements + className + attachEvent] = ((cssPrefixes - 41) - (overrideMimeType / 19));" fullword ascii
    $s16 = "isPropagationStopped = getStyles[initial + rbuggyMatches + checkbox + outerCache](holdReady + test + charCode + len);" fullword ascii
    $s17 = "access[when + delegateCount][isWindow + merge + settings + hasData](((setMatchers ^ 13377) + (file - 1301)));" fullword ascii
    $s18 = "disabled = access[holdReady + index + mimeType][left + letterSpacing + b](innerHTML + finish + settings + MAX_NEGATIVE);" fullword ascii
    $s19 = "disableScript = \"m.ar\", setMatchers = 1170, expanded = \"E\", rsubmitterTypes = \"ponse\", multipleContexts = \"WScrip\", bool" ascii
    $s20 = "progress = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    1 of ($x*) and 4 of them
}