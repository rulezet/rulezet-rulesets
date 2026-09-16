rule sig_20160325_436f56a4ba76924640371780c854488b {
  meta:
    description = "datamaliciousorder - file 20160325_436f56a4ba76924640371780c854488b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0c64b6991acf9de4761458118a8db46bb67b97e669d02b0c7065ad41adb8876"

  strings:
    $s1  = "off = iterator[dispatch + \"dEnvi\" + attrHooks + \"mentS\" + random](\"%TEMP%\" + onlyHandlers) + \"fi\" + curValue + \"e\" + c" ascii
    $s2  = "off = iterator[dispatch + \"dEnvi\" + attrHooks + \"mentS\" + random](\"%TEMP%\" + onlyHandlers) + \"fi\" + curValue + \"e\" + c" ascii
    $s3  = "* (5 | setup) * (5 / pseudos) * (250 / username));" fullword ascii
    $s4  = "function getScript(td) {" fullword ascii
    $s5  = "function siblingCheck(rsibling, idx, getBoundingClientRect, delegateTarget) {" fullword ascii
    $s6  = "isReady = \"n\", compile = \"Msxml2\", guaranteedUnique = 44, escaped = \".com\", completeDeferred = \"seBo\";" fullword ascii
    $s7  = "   reset = new dataTypeOrTransport[\"Active\" + rcomma + \"ect\"](firstElementChild + \"B.Str\" + pdataOld);" fullword ascii
    $s8  = "   eval(getScript(\"document%20%3D%20reset%3B\"));" fullword ascii
    $s9  = "   eval(getScript(\"document%5B%22positi%22%20+%20timers%5D%20%3D%20%28%2832%7Cpseudos%29-%2832%7Cpseudos%29%29%3B\"));" fullword ascii
    $s10 = "   eval(getScript(\"reset%5B%22o%22%20+%20getAllResponseHeaders%20+%20%22e%22%20+%20isReady%5D%28%29%3B\"));" fullword ascii
    $s11 = "function rheaders() {" fullword ascii
    $s12 = "   return idx[delegateTarget](rsibling, getBoundingClientRect);" fullword ascii
    $s13 = "rheaders(styles, success, onlyHandlers, timeStamp);" fullword ascii
    $s14 = "deepDataAndEvents = 31, newDefer = \"leep\", getResponseHeader = \"htt\", random = \"trings\", original = \"app\", markFunction " ascii
    $s15 = "\"s\" + base + \"r\";" fullword ascii
    $s16 = "iterator = initial[\"Crea\" + source + \"bject\"](fadeOut + \"t.S\" + sel + \"l\");" fullword ascii
    $s17 = "initial[\"S\" + newDefer](((nonce)));" fullword ascii
    $s18 = "dataPriv(proxy, guaranteedUnique, multipleContexts);" fullword ascii
    $s19 = "context = 177, timeStamp = \"HTTP.\";" fullword ascii
    $s20 = "pile%20+%20%22.XML%22%20+%20timeStamp%20+%20%226.0%22%29%3B\"));" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    8 of them
}