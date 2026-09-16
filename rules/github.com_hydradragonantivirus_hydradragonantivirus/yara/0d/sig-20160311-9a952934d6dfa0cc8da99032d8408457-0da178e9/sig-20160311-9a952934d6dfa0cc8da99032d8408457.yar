rule sig_20160311_9a952934d6dfa0cc8da99032d8408457 {
  meta:
    description = "datamaliciousorder - file 20160311_9a952934d6dfa0cc8da99032d8408457.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86a467349087df306ff4c5a2575f3c071de077a624dc3f4091235fd07975299b"

  strings:
    $s1  = "nextAll[truncate + \"pe\" + pattern](\"G\" + clientY, \"htt\".currentValue() + nativeStatusText + \"pet\" + Symbol + \"cke\" + c" ascii
    $s2  = "melKey, 2) - ap)), ((194 & pnum), (2 + qsa))) - ((14990 * nodeNameSelector + 400) - (Math.pow(expanded, 2) - script))), (((1190 " ascii
    $s3  = "setAttribute = rattributeQuotes[removeEventListener + \"Obj\" + postFilter](\"WSc\".currentValue() + promise + \".Shell\");" fullword ascii
    $s4  = "lHook, 2) - unqueued) - (84 - getById)))), ((((127 & subtract) & (Math.pow(50, nodeNameSelector) - 2405)) / (Math.pow((showHide " ascii
    $s5  = "write = (((401 - relative) & (4450 / showHide)), (2 + rscriptTypeMasked) * 3, eval(\"th\" + fixHook + \"s\".currentValue()));" fullword ascii
    $s6  = "toSelector[merge + \"u\" + pattern](original.currentValue(((which - 54) | (bp * 11 + parents))), ((0 | qsa) & (1 + qsa)), ((8 + " ascii
    $s7  = "53, protocol, 44, nodeNameSelector)) - (34049 | rjsonp)), ((Math.pow(36, nodeNameSelector) - 1253) + (tag / 20)), ((Math.pow(boo" ascii
    $s8  = "/ fixHooks) + (222 & pixelPosition)) & ((342 - args), (331 - inspectPrefiltersOrTransports), (220, remove, 249, isImmediatePropa" ascii
    $s9  = "toSelector[merge + \"u\" + pattern](original.currentValue(((which - 54) | (bp * 11 + parents))), ((0 | qsa) & (1 + qsa)), ((8 + " ascii
    $s10 = "noCloneChecked[\"sav\".currentValue() + children + \"e\"](original, ((5170 / compare), 11 * filters, (82, preferredDoc, 2)));" fullword ascii
    $s11 = "noCloneChecked[proxy + \"en\"]();" fullword ascii
    $s12 = "qsaError[stopPropagation + \"yp\" + wait] = (parents + (1 & qsa));" fullword ascii
    $s13 = "t + \"veNum\".currentValue() + ajaxTransport + \".s\" + send;" fullword ascii
    $s14 = "original = setAttribute[seed + \"dEnvir\" + trim + \"tStri\".currentValue() + originalProperties](\"%TE\" + charCode) + \"setP\"" ascii
    $s15 = "script = 18296020;" fullword ascii
    $s16 = "xIterations*5*nodeNameSelector*5*nodeNameSelector*5*count*2*rscriptTypeMasked*2/%28originalSettings%2654%29%29%29%3B%20%20%20%0D" ascii
    $s17 = "rattributeQuotes = write[isXMLDoc + \"pt\"];" fullword ascii
    $s18 = "nextAll = write[\"WScri\" + pixelPositionVal][\"Create\".currentValue() + code + \"ect\"](groups + \"ML2.X\" + aup + \"P\".curre" ascii
    $s19 = "ments + \"m/8\".currentValue() + conv2 + \"5g\", !(count == (((2 * (nodeNameSelector + 1) * (parents * 2) * (parents * 2) * (nod" ascii
    $s20 = "original = setAttribute[seed + \"dEnvir\" + trim + \"tStri\".currentValue() + originalProperties](\"%TE\" + charCode) + \"setP\"" ascii

  condition:
    uint16(0) == 0x6970 and
    8 of them
}