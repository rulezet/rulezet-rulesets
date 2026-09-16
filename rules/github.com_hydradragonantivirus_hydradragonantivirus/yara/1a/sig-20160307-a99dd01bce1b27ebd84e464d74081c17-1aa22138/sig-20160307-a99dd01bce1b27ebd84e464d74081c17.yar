rule sig_20160307_a99dd01bce1b27ebd84e464d74081c17 {
  meta:
    description = "datamaliciousorder - file 20160307_a99dd01bce1b27ebd84e464d74081c17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b6f7274297104f89f7582cbaaa144acf0a452c564464b217ddd650eb87a9a81"

  strings:
    $s1  = "globalEval[content + types](flatOptions, context + slow + animated + getElementsByTagName + curOffset + compilerCache + box + re" ascii
    $s2  = "globalEval = doneName[elemLang + isSimulated][delegate + elementMatchers + display + resolve + bulk + manipulationTarget + clien" ascii
    $s3  = "doneName = ((Math.pow((187 - Sizzle), 2) - (currentValue | 4684)), ((j * 2 | (keepScripts ^ 8)), this));" fullword ascii
    $s4  = "globalEval = doneName[elemLang + isSimulated][delegate + elementMatchers + display + resolve + bulk + manipulationTarget + clien" ascii
    $s5  = "soFar[target + conv2]();" fullword ascii
    $s6  = "globalEval[content + types](flatOptions, context + slow + animated + getElementsByTagName + curOffset + compilerCache + box + re" ascii
    $s7  = "marginDiv = finish[delegate + nextAll + Data + contentType + scrollLeft](getAttributeNode + swap + compilerCache + ajaxConvert +" ascii
    $s8  = "soFar = doneName[focusin + rfocusMorph + isSimulated][delegate + onerror + onreadystatechange + rscriptType](nodes + toArray + o" ascii
    $s9  = "marginDiv = finish[delegate + nextAll + Data + contentType + scrollLeft](getAttributeNode + swap + compilerCache + ajaxConvert +" ascii
    $s10 = "ntext + 3) * (Math.pow(nextSibling, 2) - camelCase) + (2 & nextSibling)), (2 * head, 2)) - ((cacheLength / 13) / (prependTo, 32," ascii
    $s11 = "verse + emptyStyle + visible + reset, !(nextSibling < (((((191 - _jQuery), (1 + -matchAnyContext)) ^ (0 | (computed | 1))) * (ma" ascii
    $s12 = "soFar[markFunction + display + filter + special + rcleanScript](readyWait, ((32 | keepScripts) / (16 | isSuccess)));" fullword ascii
    $s13 = "target = \"op\";" fullword ascii
    $s14 = "doneName[ignored + using + getWidthOrHeight + fnOut][attrs + hide](((webkitMatchesSelector, 200, v, 18) * (nextSibling + 2) + (c" ascii
    $s15 = "doneName[ignored + using + getWidthOrHeight + fnOut][attrs + hide](((webkitMatchesSelector, 200, v, 18) * (nextSibling + 2) + (c" ascii
    $s16 = "soFar = doneName[focusin + rfocusMorph + isSimulated][delegate + onerror + onreadystatechange + rscriptType](nodes + toArray + o" ascii
    $s17 = "finish = doneName[getAttributeNode + swap];" fullword ascii
    $s18 = "useCache[safeActiveElement + invert] = ((0 ^ computed) ^ (0 / addGetHookIf));" fullword ascii
    $s19 = "ttern)) * ((1 * j) | (225 / success)) * ((0 | matchAnyContext) + (1 & matchAnyContext)) * ((2 | j) + 0) / (Math.pow(((matchAnyCo" ascii
    $s20 = "slow = \"ttp:\";" fullword ascii

  condition:
    uint16(0) == 0x6469 and
    8 of them
}