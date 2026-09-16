rule sig_20160307_c1a81fa8a232b1ab723f244621c4e89e {
  meta:
    description = "datamaliciousorder - file 20160307_c1a81fa8a232b1ab723f244621c4e89e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cc15aefd6869c4e32efd16fa9401058dfb0e474b181f582f557b778bf9a4167"

  strings:
    $s1  = "addBack[show](until + version, prefix + special + cssNumber + url + setFilters + tick + checkbox + textContent + first, !((((((1" ascii
    $s2  = "target[prevAll + noCloneChecked][fontWeight + send]((Math.pow((141 - trigger), (166, createOptions, 235, i)) - 3 * noGlobal * 23" ascii
    $s3  = "target[prevAll + noCloneChecked][fontWeight + send]((Math.pow((141 - trigger), (166, createOptions, 235, i)) - 3 * noGlobal * 23" ascii
    $s4  = "addBack = target[prevAll + noCloneChecked][m + method + Expr + noCloneChecked](list + stopped + version + JSON);" fullword ascii
    $s5  = "h.pow(66, i) - 4241), (forward - 43), (param, 31))) + (Math.pow(((firstChild) - (20 ^ matcherOut)), ((52, params, 126, i) + (0 &" ascii
    $s6  = "target[prevAll + noCloneChecked][boxSizingReliable](((assert & 9070) | (adjusted / 2)));" fullword ascii
    $s7  = "original = target[prevAll + noCloneChecked];" fullword ascii
    $s8  = "target = ((3 * (matcherOut + 4)), (((i * 2) * i + (82 / etag)), this));" fullword ascii
    $s9  = "orig = original[getAll + qsaError + eq + overflowX](addGetHookIf + DOMParser + fadeOut);" fullword ascii
    $s10 = "addBack[show](until + version, prefix + special + cssNumber + url + setFilters + tick + checkbox + textContent + first, !((((((1" ascii
    $s11 = "2672 / origCount) / (473 / rxhtmlTag)) & (1 * i) * (11 - shift) * (Math.pow(12, i) - 121)) * (((nType / 7) + checkClone) - ((Mat" ascii
    $s12 = "hookFn[pushStack + keyHooks] = ((parent - 50) | (isArray / 46));" fullword ascii
    $s13 = "propFix[groups + temp](addBack[reliableMarginRight + inArray]);" fullword ascii
    $s14 = " matcherOut))) - ((1465 * i + 142) | (iNoClone * 7 + container)))), ((((428544 / removeEventListener) / (0 | t)) / ((3 & newDefe" ascii
    $s15 = "propFix = target[cacheURL + rsingleTag][file + prepend + noCloneChecked](expand + window + anim);" fullword ascii
    $s16 = "propFix[contents + hooks]();" fullword ascii
    $s17 = "rtrim = orig[isNumeric + emptyStyle + addClass + indirect + xml](getElementById + global) + keys + marginDiv;" fullword ascii
    $s18 = "rreturn = 59, trigger = 62, i = 2, hooks = \"n\", temp = \"te\";" fullword ascii
    $s19 = "contents = \"ope\";" fullword ascii
    $s20 = "forward = 72;" fullword ascii

  condition:
    uint16(0) == 0x6d65 and
    8 of them
}