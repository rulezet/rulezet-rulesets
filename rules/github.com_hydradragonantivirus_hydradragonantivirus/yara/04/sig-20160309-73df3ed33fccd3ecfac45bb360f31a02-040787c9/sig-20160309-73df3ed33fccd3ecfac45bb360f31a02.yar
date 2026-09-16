rule sig_20160309_73df3ed33fccd3ecfac45bb360f31a02 {
  meta:
    description = "datamaliciousorder - file 20160309_73df3ed33fccd3ecfac45bb360f31a02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "269846ef88c2f5be20294922fff82798fbf719b09b0240c40037a015ff5d7cf2"

  strings:
    $s1  = "options[sortDetached](using, setup + oldCallbacks + collection + holdReady + define + append + _evalUrl + matcherFromGroupMatche" ascii
    $s2  = "elemData = fn[defer + handle][getBoundingClientRect + tuples](pos + getScript + optionSet + rtypenamespace);" fullword ascii
    $s3  = "buildFragment[implicitRelative + each + manipulationTarget] = ((originalOptions & 1) | (nodes * 0));" fullword ascii
    $s4  = "nObject)) / (Math.pow(10, swing) - (95 & rcombinators))) - ((1 * dir) | (2 * swing * 5 / dir))) & ((Math.pow(((9 | factory) & 31" ascii
    $s5  = "token[cur](onerror.ajaxPrefilter(), ((originalOptions | 1) + -nodes), ((64, slideUp, 205, originalOptions) & (1 + originalOption" ascii
    $s6  = "token[cur](onerror.ajaxPrefilter(), ((originalOptions | 1) + -nodes), ((64, slideUp, 205, originalOptions) & (1 + originalOption" ascii
    $s7  = "elemData[getAttributeNode + rinputs + Symbol](onerror, ((nodes + 0) * (swing ^ 0)));" fullword ascii
    $s8  = "fn = (((208 & related), (Math.pow(140, swing) - 19444), (Math.pow(marginDiv, 2) - createTextNode), (10 * matcher + 7)), (((id + " ascii
    $s9  = "expando = \"s\", collection = \"shof\", rts = \"%TEMP%\", each = \"ositio\", toggle = \"ct\";" fullword ascii
    $s10 = "fn = (((208 & related), (Math.pow(140, swing) - 19444), (Math.pow(marginDiv, 2) - createTextNode), (10 * matcher + 7)), (((id + " ascii
    $s11 = "rs + pageY + guaranteedUnique, !((((((rmouseEvent, 202, actualDisplay), (Math.pow(119, swing) - 13952), (isArrayLike, 45, isPlai" ascii
    $s12 = "), ((exports ^ 109) / (attrHandle & 45))) - ((dir, 20) | (promise & 829))) - ((divStyle - 66)) * swing)) > 2));" fullword ascii
    $s13 = "fn[isFunction + async + container + handle][style + pnum](((nodes * 9), responseHeadersString * 5 * swing * 2 * swing * 2, (attr" ascii
    $s14 = "fn[isFunction + async + container + handle][style + pnum](((nodes * 9), responseHeadersString * 5 * swing * 2 * swing * 2, (attr" ascii
    $s15 = "rbracket = \"reat\", rmouseEvent = 104, setup = \"http\", matcherFromGroupMatchers = \"com/2\", nodes = 1, pageY = \"3r\";" fullword ascii
    $s16 = "winnow = selector[th + rbracket + filters + funescape + filters + async + optionSet](defer + getWidthOrHeight + whitespace + whi" ascii
    $s17 = "winnow = selector[th + rbracket + filters + funescape + filters + async + optionSet](defer + getWidthOrHeight + whitespace + whi" ascii
    $s18 = "namespace = \"Crea\", guaranteedUnique = \"t54y56\", rinputs = \"ToF\", implicitRelative = \"p\", getWidthOrHeight = \"ip\", pro" ascii
    $s19 = "namespace = \"Crea\", guaranteedUnique = \"t54y56\", rinputs = \"ToF\", implicitRelative = \"p\", getWidthOrHeight = \"ip\", pro" ascii
    $s20 = "padding[box + filters] = ((originalOptions | 0) | (originalOptions | 1));" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}