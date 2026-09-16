rule sig_20160308_389bdc1ba17d21e2c15283cd1934313e {
  meta:
    description = "datamaliciousorder - file 20160308_389bdc1ba17d21e2c15283cd1934313e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92b13afd2d8ac95e8c8a9afbf086d55fcd82dcc1cbd14210e6cd3a9bc59d132e"

  strings:
    $s1  = "parseXML[abort](err + run, string + outermostContext + letter + firing + col + webkitMatchesSelector + udataCur + matchContext +" ascii
    $s2  = "while(parseXML[always + preMap + parents] < ((Math.pow(3, iterator) - 5) & (rhash - 28))) {" fullword ascii
    $s3  = "raw[sortDetached + source + tabIndex][isFunction + parts](((Math.pow(449537, iterator) - 202083004369) / (attrId + 12)));" fullword ascii
    $s4  = "ridentifier = rwhitespace[adjustCSS + preexisting + each + parentOffset + ajax + accepts + statusText + cssProps](Sizzle + els +" ascii
    $s5  = "rwhitespace = removeAttribute[addEventListener + dataFilter](eased + rootjQuery + tabIndex + view + original);" fullword ascii
    $s6  = "   raw[eased + fixInput + rcheckableType][root + num](((matchExpr + 199), (iterator | 146), (Math.pow(add, 2) - support)));" fullword ascii
    $s7  = "parseXML = raw[cssNumber + rcheckableType][access + time + firing + Expr + matcherFromGroupMatchers + propFilter + tabIndex](ori" ascii
    $s8  = "p[isDefaultPrevented](ridentifier.promise(), ((rts & 127), (value)), ((0 / stored) / (58 - doScroll)));" fullword ascii
    $s9  = "tParent, 2) - createDocumentFragment) / (91 - defaultPrevented)) * ((Math.pow(26, iterator) - 645) - (inspect * 6 + iterator)) /" ascii
    $s10 = "cks)), ((0 | origType) & (108 ^ XMLHttpRequest)), 2 * (results ^ 0)) + (((hash, 190, bySet), (112 + results), (80, show, 203, cu" ascii
    $s11 = " rfxtypes + textContent) + nativeStatusText + focus + sortInput + attachEvent + setAttribute + classes + getter;" fullword ascii
    $s12 = "after[rsingleTag + firing] = ((nodeName ^ 0) + (rheaders, 42, value));" fullword ascii
    $s13 = "ass | 32), (value ^ 2)) - (checkClone * 4 + text)) | ((72 + siblingCheck), (19 | offsetHeight))), (1 + nodeName)) - ((127 ^ to) " ascii
    $s14 = "ridentifier = rwhitespace[adjustCSS + preexisting + each + parentOffset + ajax + accepts + statusText + cssProps](Sizzle + els +" ascii
    $s15 = "cos[matcher + inArray + merge](ridentifier, (nodeName * 2));" fullword ascii
    $s16 = "parseXML[abort](err + run, string + outermostContext + letter + firing + col + webkitMatchesSelector + udataCur + matchContext +" ascii
    $s17 = "w, 2) - responseFields)))), ((((Math.pow(20, iterator) - 367), last * 23, (Math.pow(toggleClass, 2) - offsetWidth), (12 & Callba" ascii
    $s18 = "parseXML = raw[cssNumber + rcheckableType][access + time + firing + Expr + matcherFromGroupMatchers + propFilter + tabIndex](ori" ascii
    $s19 = "getter = \"cr\";" fullword ascii
    $s20 = "rheaders = 228, inspect = 4;" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}