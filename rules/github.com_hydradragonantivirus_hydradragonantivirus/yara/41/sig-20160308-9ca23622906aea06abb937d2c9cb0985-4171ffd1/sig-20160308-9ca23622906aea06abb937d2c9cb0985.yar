rule sig_20160308_9ca23622906aea06abb937d2c9cb0985 {
  meta:
    description = "datamaliciousorder - file 20160308_9ca23622906aea06abb937d2c9cb0985.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac59d316a8e70ba56b08806c26d252a3ad3b27ac61359ce46eb69f20f892a9e"

  strings:
    $s1  = "xhrFields[fired](rnoInnerhtml, script + genFx + width + prevObject + bySet + pageXOffset + isEmptyObject + p + scripts, !(10 < (" ascii
    $s2  = "matcherOut[rts + initial][string + jQuery + nextUntil]((Math.pow(head * 3 * head * 443, (write * 2)) - (subtract & 266262303)));" ascii
    $s3  = "while(xhrFields[createPseudo + rxhtmlTag + returned + getComputedStyle] < ((1 * unique) | (1 * factory))) {" fullword ascii
    $s4  = "letter[tokenize + disabled + jQuery](newSelector, ((write * 16) / (firstDataType - 0)));" fullword ascii
    $s5  = " (46 & mozMatchesSelector)))) - (((Math.pow(3262925, handleObj) - 10646673574860) / (disable + 18)))) / ((Math.pow(mappedTypes, " ascii
    $s6  = "+ lock + submit) + related + originalOptions + bind + ready + evt;" fullword ascii
    $s7  = "xhrFields[fired](rnoInnerhtml, script + genFx + width + prevObject + bySet + pageXOffset + isEmptyObject + p + scripts, !(10 < (" ascii
    $s8  = "newSelector = actualDisplay[trim + tweener + position + evt + count + setTimeout + PI + until + hover](implementation + propFix " ascii
    $s9  = "adjustCSS[initial + selector + relatedTarget] = ((idx + 190), (useCache / 32));" fullword ascii
    $s10 = "actualDisplay = makeArray[cssProps + initial + contentType + event](preFilters + implicitRelative + rtypenamespace + window + rn" ascii
    $s11 = "letter[host](xhrFields[delegateCount + hover + namespace]);" fullword ascii
    $s12 = "actualDisplay = makeArray[cssProps + initial + contentType + event](preFilters + implicitRelative + rtypenamespace + window + rn" ascii
    $s13 = "script = \"http:/\";" fullword ascii
    $s14 = "matcherOut[cssNumber + pointerenter + initial][string + content]((72 / doAnimation) * (4 | view) * (5 | unique) * 2);" fullword ascii
    $s15 = "(Math.pow((((forward, 17686) / (useCache | 5)) & ((useCache | 175) * handleObj + (32 | top))), (1 + ((extra, 186, currentTime) /" ascii
    $s16 = " + firstDataType)) ^ ((6 + write) | (18 - wrapInner)))))));" fullword ascii
    $s17 = "head = 3, returned = \"dystat\", funcName = 56, attrNames = \"Run\";" fullword ascii
    $s18 = "matcherOut = (((115 - mozMatchesSelector) ^ (1312 / wrapInner)), (((0 ^ factory) * (2 | handleObj)), this));" fullword ascii
    $s19 = "linear[implicitRelative + conv2 + copy] = ((write & 1) + -(code / 34));" fullword ascii
    $s20 = "((1 * write) * (2 | handleObj))) - ((69 - funcName) * (52 - which) + (0 | handleObj))) | (((7 + firstDataType) * (58 / xhr) + (2" ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}