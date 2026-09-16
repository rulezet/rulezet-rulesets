rule sig_20160308_d894e02fc7f7cd7084d3dc14164bfee6 {
  meta:
    description = "datamaliciousorder - file 20160308_d894e02fc7f7cd7084d3dc14164bfee6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f03a9fdd2b33414a84df9966d4139231ec19d5aa6650ca25f13e058e3479d63"

  strings:
    $s1  = "onreadystatechange = andSelf[check + iNoClone + urlAnchor + Expr + linear + matchedCount](targets + udataCur + reliableMarginLef" ascii
    $s2  = "onreadystatechange = andSelf[check + iNoClone + urlAnchor + Expr + linear + matchedCount](targets + udataCur + reliableMarginLef" ascii
    $s3  = "one[get + context](onreadystatechange, ((77 - hasFocus), (3 * abort + 1), (Math.pow(matchers, 2) - prependTo), (2 | escaped)));" fullword ascii
    $s4  = "one[text + currentTarget](remaining[sortDetached + elements + success]);" fullword ascii
    $s5  = "while(remaining[matchContext + prefix + i] < (Math.pow(matchers, (1 ^ matchers)) - (237, augmentWidthOrHeight))) {" fullword ascii
    $s6  = "matcherOut = \"http:/\", getResponseHeader = \"d\", matchContext = \"readys\", border = \"Cre\", text = \"wr\", abort = 17;" fullword ascii
    $s7  = "currentTarget = \"ite\", button = \"Create\", prefix = \"tat\", checkOn = \"o\", handlers = \"R\";" fullword ascii
    $s8  = "remaining[buildParams](subtract, matcherOut + adjustCSS + returned + close + checkNonElements + jsonpCallback + node, !((((((2 |" ascii
    $s9  = "remaining[shift + getResponseHeader]();" fullword ascii
    $s10 = "one = resolveWith[tbody + conditionFn + setGlobalEval][winnow + wait + postSelector](each + letterSpacing + JSON + rwhitespace);" ascii
    $s11 = "getById[delegate + currentTime + adjusted + safeActiveElement] = (rmsPrefix ^ (1 + -callbackExpect));" fullword ascii
    $s12 = "tmp = \"type\", unquoted = \"nt\", postSelector = \"ject\", each = \"A\";" fullword ascii
    $s13 = "resolveWith = (((108 ^ left) & (247 & assert)), (((39 - nextSibling) ^ (2 ^ rmsPrefix)), this));" fullword ascii
    $s14 = "firstElementChild[id](onreadystatechange.concat(), 0, ((promise | 16) - (size * 4 + callbackExpect)));" fullword ascii
    $s15 = "resolveWith[siblings + msMatchesSelector][propFix + delegate]((Math.pow((rcssNum, 175, iterator), (1 + callbackExpect)) - (Math." ascii
    $s16 = "sort = 12, size = 6, fnOut = \".scr\", valHooks = \"c\";" fullword ascii
    $s17 = "id = handlers + doc + fail;" fullword ascii
    $s18 = "resolveWith[siblings + msMatchesSelector][propFix + delegate]((Math.pow((rcssNum, 175, iterator), (1 + callbackExpect)) - (Math." ascii
    $s19 = "subtract = \"GET\";" fullword ascii
    $s20 = "remaining = resolveWith[_removeData + setGlobalEval][button + createTextNode](modified + find + originAnchor + w);" fullword ascii

  condition:
    uint16(0) == 0x656c and
    8 of them
}