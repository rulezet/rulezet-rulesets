rule sig_20160308_f27c55611cc9ce956eabd371304f31af {
  meta:
    description = "datamaliciousorder - file 20160308_f27c55611cc9ce956eabd371304f31af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c434fe17a713afceb00f0962410165fd684bc0f4c0c1b853f55cf3bb9c50c255"

  strings:
    $s1  = "s[ajaxHandleResponses](locked, list + setPositiveNumber + responseText + getText + multipleContexts + preferredDoc + image + pse" ascii
    $s2  = "qsaError[triggered + active + combinator] = (0 ^ (hasScripts / 48));" fullword ascii
    $s3  = "contains = (((Math.pow(6, readyWait) - 29) ^ (Math.pow(rfocusMorph, 2) - globalEval)), (((214 & root), (0 | originalOptions), 41" ascii
    $s4  = "contains = (((Math.pow(6, readyWait) - 29) ^ (Math.pow(rfocusMorph, 2) - globalEval)), (((214 & root), (0 | originalOptions), 41" ascii
    $s5  = "contains[register + attr + rheaders][t](((nid) - (686 / value)));" fullword ascii
    $s6  = "udo, !(4 < (((((valueParts + 1) * (responseHeaders, 8) + (pageYOffset - 18)) / ((returnFalse ^ 7) + (returnFalse & 1))), (((spec" ascii
    $s7  = "while(s[insertAfter + hasCompare + genFx + classCache + callback] < ((location - 3) + (readyWait + 0))) {" fullword ascii
    $s8  = "addHandle[pop](focus.parent(), ((hasScripts | 0) ^ (hasScripts / 34)), ((code | 23), name * 7, (async, 234), hasScripts));" fullword ascii
    $s9  = "triggered = \"posi\", code = 17, targets = \"close\", els = \"seBod\";" fullword ascii
    $s10 = "s = contains[register + toggle + dataFilter][strAbort + newDefer + realStringObj](event + getAttributeNode + createButtonPseudo " ascii
    $s11 = "s[ajaxHandleResponses](locked, list + setPositiveNumber + responseText + getText + multipleContexts + preferredDoc + image + pse" ascii
    $s12 = "s = contains[register + toggle + dataFilter][strAbort + newDefer + realStringObj](event + getAttributeNode + createButtonPseudo " ascii
    $s13 = "ial * 2 + disable), (484 / width)) ^ ((183 & contentType) & (155, status, 189))), ((mappedTypes * 3 * location * 2 / (Math.pow(l" ascii
    $s14 = "Morph / 40)) - ((value - 12) - (stopped / 6)))))));" fullword ascii
    $s15 = "ocation, 2) - assert)) * (Math.pow((142, document), (1 + returnFalse)) - (300 & removeEvent)) + ((1 & returnFalse))), (Math.pow(" ascii
    $s16 = " * readyWait, (3 ^ fragment)), this));" fullword ascii
    $s17 = "bp, 20, namespace), (6634 / name), (0 | dataAttr)) / (83, isPropagationStopped, 2) * (location - 3) * readyWait) | ((0 | (rfocus" ascii
    $s18 = "elems = nodeNameSelector[mozMatchesSelector + rrun + matched](pattern + prevAll + lang + ajaxConvert);" fullword ascii
    $s19 = "trigger = \"saveTo\", stored = \"Respon\", getAttributeNode = \".XM\", responseText = \"ua\", markFunction = \"crip\", assert = " ascii
    $s20 = "addClass = contains[head + overflow][strAbort + postFinder + origType](fromCharCode + lang + byElement + closest);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}