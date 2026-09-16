rule sig_20160309_223dc823d05c4e74e078cee7791308c7 {
  meta:
    description = "datamaliciousorder - file 20160309_223dc823d05c4e74e078cee7791308c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2085fc9c2cbe0941b5d9adfba8de278bb05179b84ff9a561737646e079884dd1"

  strings:
    $x1  = "parents[simulate + password](addBack, state + checkOn + newCache + tfoot + propName + currentTarget + dataAndEvents + push + dat" ascii
    $s2  = "jqXHR[getScript + getElementsByName] = ((22 | rnative), (45 & reliableMarginLeft), (4 - once));" fullword ascii
    $s3  = "parents[simulate + password](addBack, state + checkOn + newCache + tfoot + propName + currentTarget + dataAndEvents + push + dat" ascii
    $s4  = "parents = marginDiv[err + ofType][ajax + support + overwritten + requestHeadersNames + curLeft](keepData + visibility + tokens +" ascii
    $s5  = "parents = marginDiv[err + ofType][ajax + support + overwritten + requestHeadersNames + curLeft](keepData + visibility + tokens +" ascii
    $s6  = "html[simulate + password]();" fullword ascii
    $s7  = " setMatchers + specified + password + nextSibling + fadeIn;" fullword ascii
    $s8  = "html[requestHeaders + orig](isReady, ((rnative + 0) ^ once));" fullword ascii
    $s9  = "isReady = buildParams[delegate + optionSet + clientY + rejectWith + tr + cssPrefixes + hasDuplicate](curPosition + properties) +" ascii
    $s10 = "token[nodeIndex + tokenCache] = ((0 | fadeToggle) / (3 * forward + 1));" fullword ascii
    $s11 = "password = \"n\";" fullword ascii
    $s12 = "marginDiv = (((23 ^ node) | (Math.pow(146, escapedWhitespace) - 21152)), (((once + 16) | (rnative & 0)), this));" fullword ascii
    $s13 = "(((Math.pow(matcher, 2) - statusCode) / 2 * escapedWhitespace) / ((2 | fadeToggle) * 13)))) > rnative));" fullword ascii
    $s14 = "lock[childNodes](isReady.callbackContext(), ((1 ^ fadeToggle) + -(1 * rnative)), ((8 ^ bp) - (24 | rnative)));" fullword ascii
    $s15 = "mouseHooks = \"ogs/98\", forward = 9;" fullword ascii
    $s16 = "s = \"Bo\", ignored = \"write\", which = \"ct\", getElementsByName = \"pe\";" fullword ascii
    $s17 = "unit = parents[children + isEmptyObject + opt + s + global];" fullword ascii
    $s18 = "html = marginDiv[e + gotoEnd][ajax + rts + marginLeft + which](conv + rquery + outermostContext + status);" fullword ascii
    $s19 = "support = \"eat\", remaining = 2614;" fullword ascii
    $s20 = "Toggle) | (0 & rnative))) ^ (Math.pow(((207, parseHTML, 92, escapedWhitespace) + (1 * escapedWhitespace)), (((1066 + remaining) " ascii

  condition:
    uint16(0) == 0x7369 and
    1 of ($x*) and 4 of them
}