rule sig_20160311_66f5fc6dd3208d9ce9443bbeff750bed {
  meta:
    description = "datamaliciousorder - file 20160311_66f5fc6dd3208d9ce9443bbeff750bed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e08d59cbc345f50cb49ef4841ea3800ade176b49cae0b5ff7241d4a3c5c0eea3"

  strings:
    $s1  = "curCSS[\"op\" + pageY](\"G\" + locked + \"T\".firingIndex(), rjsonp + \"://\" + isArrayLike + \"rdicke\" + stopOnFalse + \"m/8\"" ascii
    $s2  = "pipe) & 1))) * ((((rcombinators * 6) & (Math.pow(tweeners, 2) - offsetWidth)) * (2 & delay) * (79, text, 2) * (rcombinators + 1)" ascii
    $s3  = ") / (((pipe | 65), (offsetWidth - 1)) | ((pipe | 3) + (tweeners + 1)))))));" fullword ascii
    $s4  = "curCSS = deep[hookFn + \"ript\".firingIndex()][relatedTarget + \"ateOb\" + lang](\"MSXM\" + all + \"MLHT\".firingIndex() + names" ascii
    $s5  = "deep = (((475 - thead) - (76 * delay)), 2, eval(\"t\" + postMap + \"s\".firingIndex()));" fullword ascii
    $s6  = "err = subordinate[\"Exp\" + overflowX + \"nviro\".firingIndex() + outermostContext + \"Stri\" + risSimple](\"%TE\" + el + \"/\"." ascii
    $s7  = "pseudo[\"c\" + getter + \"ose\"]();" fullword ascii
    $s8  = "holdReady = deep[andSelf + \"pt\"];" fullword ascii
    $s9  = "pipe = 0;" fullword ascii
    $s10 = "pipe%29%29%3B%0D\"));" fullword ascii
    $s11 = "getter = \"l\";" fullword ascii
    $s12 = "err = subordinate[\"Exp\" + overflowX + \"nviro\".firingIndex() + outermostContext + \"Stri\" + risSimple](\"%TE\" + el + \"/\"." ascii
    $s13 = "curValue[\"saveT\".firingIndex() + elemLang](err, (1 * delay));" fullword ascii
    $s14 = "curCSS[\"op\" + pageY](\"G\" + locked + \"T\".firingIndex(), rjsonp + \"://\" + isArrayLike + \"rdicke\" + stopOnFalse + \"m/8\"" ascii
    $s15 = "dataTypeOrTransport = subordinate;" fullword ascii
    $s16 = "subordinate = holdReady[id + \"teO\" + showHide + \"t\".firingIndex()](uniqueCache + \"t.Sh\" + progress);" fullword ascii
    $s17 = "dataTypeOrTransport[iNoClone + \"n\"](err.firingIndex(((34 | delay) * (2 | delay) + (21 & oldCallbacks))), (0 / fontWeight), (0 " ascii
    $s18 = "dataTypeOrTransport[iNoClone + \"n\"](err.firingIndex(((34 | delay) * (2 | delay) + (21 & oldCallbacks))), (0 / fontWeight), (0 " ascii
    $s19 = "progress = \"ell\";" fullword ascii
    $s20 = "delay = 2;" fullword ascii

  condition:
    uint16(0) == 0x6f6c and
    8 of them
}