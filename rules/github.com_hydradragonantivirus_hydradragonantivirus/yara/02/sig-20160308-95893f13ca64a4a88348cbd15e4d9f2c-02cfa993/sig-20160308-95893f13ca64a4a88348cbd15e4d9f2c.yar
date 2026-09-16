rule sig_20160308_95893f13ca64a4a88348cbd15e4d9f2c {
  meta:
    description = "datamaliciousorder - file 20160308_95893f13ca64a4a88348cbd15e4d9f2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00885f948e447396c41a84d1f44211340c3456dbd2fffb16ad0fb839f7302cd3"

  strings:
    $x1  = "rcombinators[delegateTarget](ifModified + fired, hasOwnProperty + fromCharCode + emptyStyle + onabort + abort + pixelPositionVal" ascii
    $s2  = "rscriptTypeMasked = refElements[keyCode + image + getComputedStyle](setFilters + len + animation + qsa);" fullword ascii
    $s3  = "rcombinators[delegateTarget](ifModified + fired, hasOwnProperty + fromCharCode + emptyStyle + onabort + abort + pixelPositionVal" ascii
    $s4  = "rcombinators = onreadystatechange[slideUp + hasScripts + unmatched][tweens + reverse + one + then](maxWidth + compile + querySel" ascii
    $s5  = "rcombinators = onreadystatechange[slideUp + hasScripts + unmatched][tweens + reverse + one + then](maxWidth + compile + querySel" ascii
    $s6  = "ooks, 41, runescape, 1) | childNodes) - (((108 - script) - (9 ^ nativeStatusText)), (Math.pow((56 | dirrunsUnique), (1 * childNo" ascii
    $s7  = "2 + text)) & ((72, host, 39) - (createOptions | 32)))) * (((clearCloneStyle ^ 100) / (what, 230, firstElementChild, 5)) * ((fixH" ascii
    $s8  = "camel = 5, hasScripts = \"ip\", fired = \"T\", callbackContext = \"/\", delegateTarget = \"open\", duplicates = \"c\";" fullword ascii
    $s9  = "toSelector = rscriptTypeMasked[trim + andSelf + dataAndEvents + attr + context + once + hasDuplicate](obj + responseType + callb" ascii
    $s10 = " + matched + fragment, !((((0 ^ opacity) * (9 * scripts + 1)) * ((childNodes & 3) + (text | 0)) * ((text ^ 141), childNodes), ((" ascii
    $s11 = "ackContext) + register + push_native + pipe + removeEventListener;" fullword ascii
    $s12 = "}, 0), queue = \"m\", childNodes = 2, unmatched = \"t\", hasOwnProperty = \"http:\", _jQuery = 14;" fullword ascii
    $s13 = "wrapMap[buildParams](toSelector.activeElement(), ((120 & fxNow), (1 & text)), (144, (opacity + -1)));" fullword ascii
    $s14 = "createFxNow[nextSibling + factory] = ((text | 1) * (opacity + -1));" fullword ascii
    $s15 = "(32 | createOptions) - (3 & rcheckableType))), (77, uid, 2) * ((opacity + -1) ^ (text | 2)) * (childNodes & 3), ((childNodes | (" ascii
    $s16 = "refElements = onreadystatechange[rclickable + dequeue + unmatched];" fullword ascii
    $s17 = "beforeunload[slow + offsetParent](rcombinators[cloneCopyEvent + cssPrefixes + wrapAll]);" fullword ascii
    $s18 = "beforeunload[interval + rcomma]();" fullword ascii
    $s19 = "while(rcombinators[dataAttr + sortOrder + unmatched + rmultiDash] < ((text | 4) ^ (text / 45))) {" fullword ascii
    $s20 = "des)) - (Math.pow(9989, childNodes) - 99765859)), (childNodes * 2 * childNodes * 2 ^ (Math.pow(rcheckableType, 2) - camel)), ((8" ascii

  condition:
    uint16(0) == 0x7266 and
    1 of ($x*) and 4 of them
}