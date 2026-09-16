rule sig_20160307_452e81ccde744f7ae2a167a3f81c6a1a {
  meta:
    description = "datamaliciousorder - file 20160307_452e81ccde744f7ae2a167a3f81c6a1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcdc8ba7a759e81d7a151e897755dd8505f04e77116dad6f4947b752133c6a8c"

  strings:
    $s1  = "specialEasing[one + createHTMLDocument + hasData + delegate](emptyGet, (special * 2 * next * 5 * special * 2, (hasScripts, 5, cl" ascii
    $s2  = "emptyGet = getComputedStyle[url + origName + startLength + targets + removeAttr + structure + curLeft](traditional + owner) + re" ascii
    $s3  = "emptyGet = getComputedStyle[url + origName + startLength + targets + removeAttr + structure + curLeft](traditional + owner) + re" ascii
    $s4  = "isDefaultPrevented[fired + overwritten](computeStyleTests + ridentifier, createOptions + jQuery + define + dataTypeExpression + " ascii
    $s5  = "specialEasing[one + createHTMLDocument + hasData + delegate](emptyGet, (special * 2 * next * 5 * special * 2, (hasScripts, 5, cl" ascii
    $s6  = "getComputedStyle = getElementsByClassName[augmentWidthOrHeight + margin + n](operator + copyIsArray + curOffset + nativeStatusTe" ascii
    $s7  = "getComputedStyle = getElementsByClassName[augmentWidthOrHeight + margin + n](operator + copyIsArray + curOffset + nativeStatusTe" ascii
    $s8  = "ose, 31), (Math.pow(fnOut, 2) - text), 2));" fullword ascii
    $s9  = " - origCount)) ^ 3) - (Math.pow(((padding ^ (1 + -padding)) + ((1 + special) ^ (7 & mouseleave))), (((Math.pow(30, special) - 85" ascii
    $s10 = "traditional = \"%TEMP%\", delegate = \"le\", fnOut = 18;" fullword ascii
    $s11 = "- 175)) + ((padding & 1) + (oldfire - 4))) * (((uniqueCache - 153), (Math.pow(children, 2) - holdReady), (221 & statusCode), (31" ascii
    $s12 = "getElementsByClassName = Sizzle[operator + rbracket + excess];" fullword ascii
    $s13 = "isDefaultPrevented[fired + overwritten](computeStyleTests + ridentifier, createOptions + jQuery + define + dataTypeExpression + " ascii
    $s14 = "delegateCount = 13099, nonce = \"pos\", one = \"s\", targets = \"men\";" fullword ascii
    $s15 = "groups[nonce + showHide + beforeunload] = ((clientTop - 15) * (padding + -1));" fullword ascii
    $s16 = "createPositionalPseudo[excess + isNumeric] = (responseText - 44);" fullword ascii
    $s17 = "_evalUrl = \"pt\", startLength = \"nviron\", hasContent = \"y\", computeStyleTests = \"GE\", split = \"Stream\";" fullword ascii
    $s18 = "0) | (special + 0)) / ((boxSizingReliableVal - 36) + (mouseleave + 7)))) - (((oldfire ^ 1) * (next & 2) + (splice / 44)) * ((nex" ascii
    $s19 = "timeout + optionSet + propFilter + callbackExpect + owner + pos + fn + createTween, !(((((437 / until) - (Math.pow(14, special) " ascii
    $s20 = "Sizzle[operator + camel][fire]((next & 2) * (special & 3) * (simple | 5) * (simple | 5));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}