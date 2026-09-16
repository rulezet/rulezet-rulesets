rule sig_20160311_ae6f8e4adac63bb4fa915f05c0748337 {
  meta:
    description = "datamaliciousorder - file 20160311_ae6f8e4adac63bb4fa915f05c0748337.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bebc4941f569ac750b7072890fd58eae58e4d9605b66d2f87fe03aab26c411d5"

  strings:
    $s1  = "optSelected[\"op\".matches() + mouseenter + \"n\"](rscriptTypeMasked + \"T\", textContent + \"//50\".matches() + escaped + \"11." ascii
    $s2  = "w = getElementsByName[\"Create\" + toArray + \"t\".matches()](responses + \"pt.She\" + memory);" fullword ascii
    $s3  = "* stopPropagation)), ((7 / step) * (1 + -overflowX)));" fullword ascii
    $s4  = "ype | 2)) - (compare | 32774)), ((compareDocumentPosition - 35) - (maxWidth * 7 + overflowX))) | ((1 & overflowX))) & (((1 + sto" ascii
    $s5  = "pPropagation) * ((187, num, 227), (genFx - 107), (compiled - 45))) * (((elemLang - 53) / (event - 15)) * (overflowX + 2)))) == m" ascii
    $s6  = "text + \"0/89o\" + dataFilter + \"u5y4\".matches(), !((((((srcElements / 35) & (compiled & 47)), (Math.pow(dataType * 3, (firstD" ascii
    $s7  = "headers = setOffset[\"WSc\" + next][\"Create\".matches() + toArray + \"t\"](rattributeQuotes + \"Stream\");" fullword ascii
    $s8  = "setOffset = ((Math.pow((57 & then), 2) - (relative - 1996)), ((hasDuplicate & 28) - (preFilters & 23)), eval(\"t\" + superMatche" ascii
    $s9  = "setOffset = ((Math.pow((57 & then), 2) - (relative - 1996)), ((hasDuplicate & 28) - (preFilters & 23)), eval(\"t\" + superMatche" ascii
    $s10 = "setGlobalEval[\"R\" + createOptions + \"n\".matches()](isSuccess.matches(((lname | 224), (jsonpCallback * 5 + dataAndEvents))), " ascii
    $s11 = "optSelected[_removeData + \"n\" + linear]();" fullword ascii
    $s12 = "ofType[\"ty\" + conditionFn + \"e\"] = ((1 + stopPropagation) * (30 / width));" fullword ascii
    $s13 = "optSelected = setOffset[\"WScri\" + before][\"Crea\".matches() + last + \"ject\"](prop + \"2.XMLH\" + createPseudo);" fullword ascii
    $s14 = "proxy();" fullword ascii
    $s15 = "function proxy() {" fullword ascii
    $s16 = "function byElement() {" fullword ascii
    $s17 = "function responseContainer() {" fullword ascii
    $s18 = "dataAndEvents = (function String.prototype.matches() {" fullword ascii
    $s19 = "var then = 57," fullword ascii
    $s20 = "relative = 5158;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}