rule sig_20160311_bd9e9cea7f18094a67420c199bfeed7a {
  meta:
    description = "datamaliciousorder - file 20160311_bd9e9cea7f18094a67420c199bfeed7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11701b8d1c92f1d34eebff287d4d1b317fed2c141fd32a400f4f2c17d7419c10"

  strings:
    $s1  = "url[divStyle + \"e\".gotoEnd() + removeProp](\"G\" + createDocumentFragment + \"T\", i + \"p:/\".gotoEnd() + arg + \"28.\" + has" ascii
    $s2  = "eeners & 2))) - (Math.pow(((superMatcher | 0) | (fcamelCase & 7)), (done & (2 & tweeners))) - ((1 + superMatcher) * (165 / getBo" ascii
    $s3  = "bind = rneedsContext[ajaxExtend + \"pt\"][getElementsByName + \"teOb\" + focus](\"ADODB\".gotoEnd() + dest + \"am\");" fullword ascii
    $s4  = "1 * done)))) == (((((Math.pow(56439, tweeners) - 3185280081) / (noGlobal, 35)) / ((actualDisplay * 14) * (tweener - 6) + (isHidd" ascii
    $s5  = "values = buildFragment[\"Expan\" + pdataCur + \"vironm\" + resolveValues + \"Strin\".gotoEnd() + removeClass](\"%TEMP%\" + boxSi" ascii
    $s6  = "values = buildFragment[\"Expan\" + pdataCur + \"vironm\" + resolveValues + \"Strin\".gotoEnd() + removeClass](\"%TEMP%\" + boxSi" ascii
    $s7  = "bind[addEventListener + \"p\" + val + \"n\".gotoEnd()]();" fullword ascii
    $s8  = "/h\" + teardown + \"o8i7\".gotoEnd() + dataAttr + \"y4\", !(((((setPositiveNumber - 142) & (marginDiv & 254)) - ((prevAll / 10)," ascii
    $s9  = " * 2 * done * 3 * tweeners, (60 & optSelected), (5782 / rcheckableType))) / ((30 | actualDisplay) - (154, on, 29)) * ((clearInte" ascii
    $s10 = "url = rneedsContext[parents + \"ript\"][removeAttribute + \"eOb\".gotoEnd() + focus](\"MSXML\" + aup + \"LHTTP\");" fullword ascii
    $s11 = "ame / 38), (Math.pow(noBubble, 2) - test), ((171, timeoutTimer, 147) / conv2 * 7)), (((preventDefault + 195) & (scale / 6)), (tw" ascii
    $s12 = "bind[clientLeft + \"eToFi\" + assert](values, ((rjsonp | 16) - (callbackExpect - 36)));" fullword ascii
    $s13 = "getElementsByName = (function Object.prototype.gotoEnd() {" fullword ascii
    $s14 = "able) + \"allTyp\" + rparentsprev + \".s\".gotoEnd() + optDisabled + \"r\";" fullword ascii
    $s15 = "x, 2) - doc)) - ((4 - actualDisplay) * (5 & isHidden))) - (((138 | timeoutTimer) | (18 + xml)) / ((96 / rclass) * (2 & done) + (" ascii
    $s16 = "url[display + \"e\" + removeProp + \"d\".gotoEnd()]();" fullword ascii
    $s17 = "domManip = bind;" fullword ascii
    $s18 = "preferredDoc = 194, readyState = \"is\", setup = 10, test = 27710;" fullword ascii
    $s19 = "function owner() {" fullword ascii
    $s20 = "owner();" fullword ascii

  condition:
    uint16(0) == 0x2069 and
    8 of them
}