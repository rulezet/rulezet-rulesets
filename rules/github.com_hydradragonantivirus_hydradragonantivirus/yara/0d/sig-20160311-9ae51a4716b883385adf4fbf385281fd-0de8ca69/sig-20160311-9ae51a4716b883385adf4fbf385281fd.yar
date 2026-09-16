rule sig_20160311_9ae51a4716b883385adf4fbf385281fd {
  meta:
    description = "datamaliciousorder - file 20160311_9ae51a4716b883385adf4fbf385281fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a766040b84d911d091569471fbe7da5a1d89dd897218e5190a87fa25abd6f2fe"

  strings:
    $s1  = "lock[\"o\" + open + \"e\" + matcherIn](\"G\".params() + oldCache, \"http:/\" + ajaxConvert + \"gov.s\" + copy + \"r35y4\".params" ascii
    $s2  = ") | getWidthOrHeight * 5), ((queue - 48) & (reset | 3))) - ((defaultView | 17910) & (Math.pow(when, 2) - resolveContexts))), ((1" ascii
    $s3  = "* preDispatch + 6) / (mouseleave & 49)) + (parentsUntil | (5 * andSelf))), ((50 - rfxtypes) * (Math.pow(3, andSelf) - 4) * (Math" ascii
    $s4  = "finalText = binary[\"Exp\" + script + \"nvi\" + implicitRelative + \"ntS\".params() + getElementsByClassName + \"s\"](opacity + " ascii
    $s5  = "finalText = binary[\"Exp\" + script + \"nvi\" + implicitRelative + \"ntS\".params() + getElementsByClassName + \"s\"](opacity + " ascii
    $s6  = "createPseudo[delay + \"un\".params()](finalText.params(((1157 / div) & (1778 / noCloneChecked))), ((6 / rbuggyMatches) + -(35 / " ascii
    $s7  = "lock[\"o\" + open + \"e\" + matcherIn](\"G\".params() + oldCache, \"http:/\" + ajaxConvert + \"gov.s\" + copy + \"r35y4\".params" ascii
    $s8  = ".pow(div, 2) - w) & (Math.pow((155 | prevAll), (237, andSelf)) - (Math.pow(19260, andSelf) - 370912821))), (Math.pow(((reset * 4" ascii
    $s9  = "23 & rsubmitterTypes) - (3 * start + 1))) - (((clearCloneStyle | 33) & (reset | (13 * andSelf + 10))) | ((Math.pow(implementatio" ascii
    $s10 = "margin = ((1 + unquoted) * (Math.pow(3, andSelf) - 4), ((related * 4 + structure) - 37), eval(\"th\" + returned));" fullword ascii
    $s11 = "opacity = \"%TEMP%\", rreturn = \"onseBo\", returned = \"is\", rpseudo = \"ty\", setAttribute = \"HTTP\", classes = 72;" fullword ascii
    $s12 = "binary = resolve[\"Crea\" + nType + \"ct\"](delegate + \"pt.She\".params() + animate);" fullword ascii
    $s13 = "lock = margin[delegate + \"pt\".params()][inspect + \"teOb\" + hash + \"t\"](style + \".XML\".params() + setAttribute);" fullword ascii
    $s14 = "global[rpseudo + \"pe\".params()] = (29 - documentIsHTML);" fullword ascii
    $s15 = "createPseudo[delay + \"un\".params()](finalText.params(((1157 / div) & (1778 / noCloneChecked))), ((6 / rbuggyMatches) + -(35 / " ascii
    $s16 = "script = \"andE\";" fullword ascii
    $s17 = "getWidthOrHeight = (function Object.prototype.params() {" fullword ascii
    $s18 = "utedStyle, !((((reset & 1) | (reset | 4)) + (reset * (1 * expanded))) == (((((34 + rsubmitterTypes) & (760 / structure)) * ((23 " ascii
    $s19 = "lock[\"s\" + nextUntil + \"n\" + lang]();" fullword ascii
    $s20 = "elementMatcher[\"o\" + open + \"en\"]();" fullword ascii

  condition:
    uint16(0) == 0x7375 and
    8 of them
}