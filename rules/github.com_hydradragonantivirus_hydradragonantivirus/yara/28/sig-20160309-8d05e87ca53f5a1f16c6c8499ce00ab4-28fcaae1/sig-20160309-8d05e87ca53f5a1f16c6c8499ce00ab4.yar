rule sig_20160309_8d05e87ca53f5a1f16c6c8499ce00ab4 {
  meta:
    description = "datamaliciousorder - file 20160309_8d05e87ca53f5a1f16c6c8499ce00ab4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7ca121ccbcf3578163036108940abcb33e6bc6ec9172ca00e14347e8f5036fd"

  strings:
    $s1  = "attrHandle[noop + classes](transports, overflowX + pseudos + finish + hover + scrollLeft + targets + winnow + url + text + rname" ascii
    $s2  = "toggle = pos[className + until + contents + createHTMLDocument + uid + offsetParent + mappedTypes](stored + callbackExpect + tex" ascii
    $s3  = "fireWith[cos + pipe] = ((1 ^ opt) + -(1 & defer));" fullword ascii
    $s4  = "attrHandle[noop + classes](transports, overflowX + pseudos + finish + hover + scrollLeft + targets + winnow + url + text + rname" ascii
    $s5  = "(parseHTML - 32), (slideDown * 2 + undelegate)))) + ((13 - success) ^ ((188, defer) | 1))) > matcherFromTokens));" fullword ascii
    $s6  = ")) & (opt | (1 + -defer))) | (((51 * undelegate + 29) / (Math.pow(qualifier, 2) - window)) - ((51, excess, 68), (matched + 18), " ascii
    $s7  = "bp = \"r\", delegateTarget = \"docEle\", finish = \"//\";" fullword ascii
    $s8  = "close = boxSizingReliableVal[eventPath + udataCur][params + ontype + notify + win](nodeNameSelector + overrideMimeType + bp + sp" ascii
    $s9  = "pos = needsContext[curLeft + unmatched + parseXML](includeWidth + argument + click + getText + bool);" fullword ascii
    $s10 = "close = boxSizingReliableVal[eventPath + udataCur][params + ontype + notify + win](nodeNameSelector + overrideMimeType + bp + sp" ascii
    $s11 = "boxSizingReliableVal = ((3 * undelegate * 53 & success * 29), (((fireGlobals - 45) & (success - 10)), this));" fullword ascii
    $s12 = "ubmitterTypes * 3 * rsubmitterTypes)) - (((30 | mouseleave) & (25 + reverse)), (5 & reverse) * (7 & reverse))) * (((1 + (opt | 0" ascii
    $s13 = "onload[init](toggle.gotoEnd(), (0 & (combinator, 156, cacheLength, 0)), ((defer * 1) + -(defer * 1)));" fullword ascii
    $s14 = "eventPath = \"WScri\", transports = \"GET\", ct = \"teObje\", win = \"t\", winnow = \"/s\", rCRLF = \"Run\";" fullword ascii
    $s15 = "var pipe = \"ion\";" fullword ascii
    $s16 = "toggle = pos[className + until + contents + createHTMLDocument + uid + offsetParent + mappedTypes](stored + callbackExpect + tex" ascii
    $s17 = "}, \"o\"), window = 86, createFxNow = \"5uy45\", contents = \"nvir\";" fullword ascii
    $s18 = "space + createElement + createFxNow + initialInUnit, !((((((prefilterOrFactory + 0) * (rsubmitterTypes ^ 1)) + ((defer + 0) * rs" ascii
    $s19 = "close[round + attr](handler);" fullword ascii
    $s20 = "attrHandle = boxSizingReliableVal[sortDetached + win][second + ct + unloadHandler](animated + origCount + nType + nodeValue);" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}