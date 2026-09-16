rule sig_20160309_136d3a9df0774ae74c6afb3aff6d52b0 {
  meta:
    description = "datamaliciousorder - file 20160309_136d3a9df0774ae74c6afb3aff6d52b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0d2c35d24b3b95b3784275bc05bf97df5a83ab234cd00029f840471891bf4f1"

  strings:
    $s1  = "isNumeric = iframe[params + contentDocument + target + noop](isArrayLike + init + uid + postMap);" fullword ascii
    $s2  = "onreadystatechange = opener[ajax + getPropertyValue + hasFocus][params + currentTime + valueParts + target + tokenize + hasFocus" ascii
    $s3  = "onreadystatechange = opener[ajax + getPropertyValue + hasFocus][params + currentTime + valueParts + target + tokenize + hasFocus" ascii
    $s4  = "onreadystatechange[all](getAll, fromCharCode + copy + last + defer + getById + tr + rmouseEvent, !((((((attrs - 145) * (nextSibl" ascii
    $s5  = "onreadystatechange[all](getAll, fromCharCode + copy + last + defer + getById + tr + rmouseEvent, !((((((attrs - 145) * (nextSibl" ascii
    $s6  = "opener[uniqueSort + hasFocus][newContext + winnow]((valHooks * 2, (runescape & 223), (Math.pow(setRequestHeader, 2) - easing)));" ascii
    $s7  = "cors = opener[uniqueSort + hasFocus][root + preFilters + proxy + hasFocus](rrun + querySelectorAll + fx + getStyles);" fullword ascii
    $s8  = "unit[token + click] = ((12 - namespace) | (0 | cssFn));" fullword ascii
    $s9  = "opener = (((10 * parseJSON + 6) * keepData + (106 - dataUser)), (((36 & qsa) - (9 * keepData + 5)), this));" fullword ascii
    $s10 = "var target = \"teOb\"," fullword ascii
    $s11 = "guaranteedUnique = onreadystatechange[timer + timerId + version + eventPath];" fullword ascii
    $s12 = "Expr) + overflowY + eventDoc + getElementById + detach;" fullword ascii
    $s13 = "rnotwhite = isNumeric[rmargin + nonce + postSelector + responseText + accepts + multipleContexts + what + _default](div1 + match" ascii
    $s14 = "rnotwhite = isNumeric[rmargin + nonce + postSelector + responseText + accepts + multipleContexts + what + _default](div1 + match" ascii
    $s15 = "originalSettings[off + contentType + matches] = ((0 ^ cssFn) ^ (0 & progress));" fullword ascii
    $s16 = "11)) * replaceChild * 3 * keepData) / (((1 + nextSibling)) + ((109, speed, 46) - (finalText ^ 6))))) > optDisabled));" fullword ascii
    $s17 = "iframe = opener[isArrayLike + detach + percent];" fullword ascii
    $s18 = "ing * 2) + prototype * 2) / ((classes, 25) + write)) + ((Math.pow((2 + progress), (1 + progress)) - (Math.pow(3, keepData) - 4))" ascii
    $s19 = "onreadystatechange[round + preferredDoc]();" fullword ascii
    $s20 = "round = \"s\", progress = 1, setRequestHeader = 14872, doneName = 55;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}