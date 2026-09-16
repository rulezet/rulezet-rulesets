rule sig_20160309_06c9eb5b2bb36f5d76cddd43a2d20b70 {
  meta:
    description = "datamaliciousorder - file 20160309_06c9eb5b2bb36f5d76cddd43a2d20b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c81100e04afa51adc14dd1c9e5edde2bbb4cec7300d1432964ec6662c554dd7"

  strings:
    $s1  = "uniqueSort[msMatchesSelector + postFilter](startLength + all, args + last + msFullscreenElement + rscriptTypeMasked + html + cap" ascii
    $s2  = "root[tokens + off][mimeType + exports + overrideMimeType + hold]((Math.pow((oldCallbacks, 9066), n) - 3 * currentValue * 139 * n" ascii
    $s3  = "root[tokens + off][mimeType + exports + overrideMimeType + hold]((Math.pow((oldCallbacks, 9066), n) - 3 * currentValue * 139 * n" ascii
    $s4  = "detectDuplicates = host[tmp + toggleClass + linear + left + fxNow + trim](hasScripts + dataTypes + hasContent) + callback + stop" ascii
    $s5  = "detectDuplicates = host[tmp + toggleClass + linear + left + fxNow + trim](hasScripts + dataTypes + hasContent) + callback + stop" ascii
    $s6  = "9, n) - 6147)), ((rreturn | 10) * (rbuggyMatches * 3) + (overflowY & 15)), ((compile + 9) & (transports - 14)), (n ^ 0))) - (Mat" ascii
    $s7  = "host = showHide[nodes + when + rmultiDash + unit](relative + Deferred + lock + funcName + exports + exports);" fullword ascii
    $s8  = "showHide = root[image + getPropertyValue];" fullword ascii
    $s9  = "h.pow(((structure & 1916) / n * 17), ((rbuggyMatches * 1) * (cloneCopyEvent & 2))) - ((testContext) + (935 - each))))) > 2));" fullword ascii
    $s10 = " + conv2)) - (0 | dataFilter)) & ((Math.pow(14, n) - 181) & (Math.pow(isArrayLike, 2) - status))), (((135 - match) + (Math.pow(7" ascii
    $s11 = "mapped = root[tokens + srcElements + rescape][getClass + winnow + opts](rts + preferredDoc + hasFocus);" fullword ascii
    $s12 = "uniqueSort[msMatchesSelector + postFilter](startLength + all, args + last + msFullscreenElement + rscriptTypeMasked + html + cap" ascii
    $s13 = "alPseudo / 20) * (removeEvent & 5)) & ((n + 2) ^ (Math.pow(high, 2) - opener))) & (Math.pow(((Math.pow((48 - responseFields), (2" ascii
    $s14 = "uniqueSort = root[head + rescape][css + argument + rescape](step + stopPropagation + defaultDisplay + removeClass + dataTypes);" fullword ascii
    $s15 = "lang = temp;" fullword ascii
    $s16 = "root = (((261 * guaranteedUnique + 165) / (writable + 10)), (((JSON / 18) & (rbuggyMatches * 3)), this));" fullword ascii
    $s17 = "Name + rwhitespace + camel + unquoted, !((((Math.pow(((n + 2) ^ (load / 29)), ((rbuggyMatches * 0) | (n + 0))) - (createPosition" ascii
    $s18 = "temp[children] = rbuggyMatches;" fullword ascii
    $s19 = "temp = mapped;" fullword ascii
    $s20 = "var head = \"WScrip\"," fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}