rule sig_20160308_a28770978024ac19a1a71c0402b6e68d {
  meta:
    description = "datamaliciousorder - file 20160308_a28770978024ac19a1a71c0402b6e68d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b84641c51ea238302fee07617598459b62263b75fd79d0e307d1372a45a1124c"

  strings:
    $s1  = "errorCallback[siblings + rdashAlpha](indirect, rheader + curValue + mouseleave + factory + groups + attachEvent + adown + global" ascii
    $s2  = "undelegate[opacity + pageY + parentsUntil + includeWidth + node](scripts, (document * 5 * forward - (60 - documentElement)));" fullword ascii
    $s3  = "s + 1) ^ (curLeft / 9)) / forward * (54 - hidden))) ^ ((1 & (removeEvent & 1)) + (progressContexts / (Math.pow(5, document) - 17" ascii
    $s4  = "scripts = binary[a + MAX_NEGATIVE + minWidth + apply + matchIndexes + map](appendTo + tuples) + doAnimation + adjusted + sibling" ascii
    $s5  = "scripts = binary[a + MAX_NEGATIVE + minWidth + apply + matchIndexes + map](appendTo + tuples) + doAnimation + adjusted + sibling" ascii
    $s6  = "calculatePosition[reliableMarginRight + animated + attrHooks][tweener + node + destElements]((rdisplayswap / 41) * (Math.pow(sto" ascii
    $s7  = "appendTo = \"%TEMP%\";" fullword ascii
    $s8  = "tings)) & (Math.pow((0 | (offsetHeight | 10)), (stop & 2)) - ((Math.pow(args, 2) - rsubmittable))))) == (((((3 * originalSetting" ascii
    $s9  = "rchecked[isBorderBox + parsed] = ((0 & progressContexts) / (Math.pow(4, document) - 11));" fullword ascii
    $s10 = " & 14)) + (ready & (3 ^ escaped)))) - ((((Math.pow(8, document) - 55) ^ (document ^ 7)) | ((originalSettings & 13) & originalSet" ascii
    $s11 = "replaceChild[els](scripts.push(), ((1 * removeEvent) * (0 / before)), ((0 & removeEvent) ^ (24 - scale)));" fullword ascii
    $s12 = "p, 2) - escaped) * (240, dataPriv, 37, forward) * 2);" fullword ascii
    $s13 = "binary = mappedTypes[parseFromString + wrapInner + contentDocument + top](concat + scrollTop + optDisabled);" fullword ascii
    $s14 = "errorCallback[siblings + rdashAlpha](indirect, rheader + curValue + mouseleave + factory + groups + attachEvent + adown + global" ascii
    $s15 = "animated = \"Scrip\", testContext = \"eBody\", parentsUntil = \"eToFi\", contentDocument = \"teObj\", curValue = \"//\", include" ascii
    $s16 = "undelegate = calculatePosition[jsonpCallback + attrHooks][parseFromString + sibling + sortInput + top](getStyles + unquoted + ur" ascii
    $s17 = "undelegate = calculatePosition[jsonpCallback + attrHooks][parseFromString + sibling + sortInput + top](getStyles + unquoted + ur" ascii
    $s18 = "animated = \"Scrip\", testContext = \"eBody\", parentsUntil = \"eToFi\", contentDocument = \"teObj\", curValue = \"//\", include" ascii
    $s19 = "indirect = \"GET\", parseFromString = \"C\", clientLeft = 44, map = \"ings\";" fullword ascii
    $s20 = "forward = 5," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}