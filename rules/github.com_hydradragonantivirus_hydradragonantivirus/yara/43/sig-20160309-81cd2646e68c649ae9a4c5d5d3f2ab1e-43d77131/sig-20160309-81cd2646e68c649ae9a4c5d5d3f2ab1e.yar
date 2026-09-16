rule sig_20160309_81cd2646e68c649ae9a4c5d5d3f2ab1e {
  meta:
    description = "datamaliciousorder - file 20160309_81cd2646e68c649ae9a4c5d5d3f2ab1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8747932d1597a56bb8e1de9b55cbbcae872de5580d9a3622cd4ade04e7dd9a95"

  strings:
    $s1  = "contents[setter + disable](contentDocument, parseHTML + prototype + firstElementChild + msFullscreenElement + t + camel + ajaxSe" ascii
    $s2  = "contents = checkOn[wrapAll + ready][ofType + clientTop](implicitRelative + postSelector + key + success);" fullword ascii
    $s3  = "tup + getElementsByName + valueIsBorderBox, !(fixHook == (((((248, relative), (560 / opt)), ((241 - ap) ^ (Math.pow(140, activeE" ascii
    $s4  = "tween = hide[MAX_NEGATIVE + prependTo + delay + what + view + nodes](handleObj + m) + visible + getScript + originalOptions + Ex" ascii
    $s5  = "tween = hide[MAX_NEGATIVE + prependTo + delay + what + view + nodes](handleObj + m) + visible + getScript + originalOptions + Ex" ascii
    $s6  = "originalEvent = checkOn[showHide + content][emptyStyle + i + webkitMatchesSelector + isFunction](thead + merge + buildFragment +" ascii
    $s7  = "originalEvent = checkOn[showHide + content][emptyStyle + i + webkitMatchesSelector + isFunction](thead + merge + buildFragment +" ascii
    $s8  = "checkOn[winnow + async + fast + always][addBack + jsonProp + rcheckableType](((Math.pow(7874, activeElement) - 61986932) | activ" ascii
    $s9  = "checkOn[winnow + async + fast + always][addBack + jsonProp + rcheckableType](((Math.pow(7874, activeElement) - 61986932) | activ" ascii
    $s10 = "handleObj = \"%TEMP%\";" fullword ascii
    $s11 = "file[padding + rnamespace + test] = ((getClass | 1) + -toSelector);" fullword ascii
    $s12 = "contents[eased + expanded]();" fullword ascii
    $s13 = "close = contents[delegateType + constructor + curPosition];" fullword ascii
    $s14 = "matchedCount = checkOn[winnow + emptyGet + checkDisplay];" fullword ascii
    $s15 = "checkOn = (((179 & returnTrue), (15 * activeElement + 11), (to & 14)), ((toSelector + 4) * (msMatchesSelector - 12), this));" fullword ascii
    $s16 = "hide = matchedCount[emptyStyle + i + createComment + content](winnow + rxhtmlTag + addCombinator + classes + noConflict);" fullword ascii
    $s17 = "dataTypeOrTransport = 26, always = \"pt\", implicitRelative = \"MSXML\", getElementsByName = \"gs/43g\", activeElement = 2;" fullword ascii
    $s18 = "le)) + ((39 - results), (68 - show), (50 | promise), (1 / toSelector)))))));" fullword ascii
    $s19 = "ctiveElement) - 19)) ^ ((fixHook + 0) * (dataTypeOrTransport / 13)))) / ((((filter | 8), (sortDetached - 238)) - ((calculatePosi" ascii
    $s20 = "key = \"XMLHTT\", addBack = \"Sl\", ofType = \"Create\", addCombinator = \"pt.Sh\", createComment = \"jec\", view = \"in\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}