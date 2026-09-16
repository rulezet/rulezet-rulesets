rule sig_20160311_64819eeec83d3b153ed65b55234e4b3b {
  meta:
    description = "datamaliciousorder - file 20160311_64819eeec83d3b153ed65b55234e4b3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "510a3f923ed35715b56522ba70f61b270774fd85f43b1f5df71e79143688f8e9"

  strings:
    $s1  = "createFxNow[boxSizingReliableVal + \"e\".udataOld() + throws](\"G\" + createDocumentFragment + \"T\", ajaxPrefilter + \"/peter\"" ascii
    $s2  = "* postDispatch) * (7 - text)) + (((0 | push_native) | (33 - realStringObj)) - ((0 / hookFn) / (18 + converters)))) | ((1 & postD" ascii
    $s3  = "matcherFromGroupMatchers = mapped[\"Cre\" + xhr + \"jec\".udataOld() + insertAfter](\"WScr\" + operator + \"Shell\");" fullword ascii
    $s4  = "get = ((2 * ontype * 2 * newUnmatched + (16 | tr)), (3 | (postDispatch + -1)), eval(\"t\" + rdisplayswap + \"i\".udataOld() + st" ascii
    $s5  = "get = ((2 * ontype * 2 * newUnmatched + (16 | tr)), (3 | (postDispatch + -1)), eval(\"t\" + rdisplayswap + \"i\".udataOld() + st" ascii
    $s6  = "dfire, 1218) / (pixelPositionVal - 61)), ((rcomma | 180)), ((classes / 1) + (rcomma + 5))) - ((Math.pow((interval, 163, parseHTM" ascii
    $s7  = "originalEvent = get[\"WSc\" + add + \"t\"][clazz + \"eOb\".udataOld() + ajaxSettings](\"ADOD\" + reset + \"ream\");" fullword ascii
    $s8  = "createFxNow = get[\"WSc\" + bp][\"Crea\" + locked + \"ct\".udataOld()](fxNow + \"2.X\" + disabled + \"TP\");" fullword ascii
    $s9  = "()) + detectDuplicates + \"xHandl\" + errorCallback + \"onses\" + step + \"s\".udataOld() + responseHeadersString;" fullword ascii
    $s10 = "proxy = matcherFromGroupMatchers[callbackName + \"Envir\".udataOld() + options + \"entSt\" + top + \"gs\"](startLength + \"%/\"." ascii
    $s11 = "opacity[\"ty\" + isFunction] = ((9 * newUnmatched + 1) - (then | 2));" fullword ascii
    $s12 = "originalEvent[amd + \"ToFil\".udataOld() + onlyHandlers](proxy, ((4 * prevAll + 1), (booleans / 33), newUnmatched));" fullword ascii
    $s13 = "d() + dataType + \"m.co\" + disable + \"745g\", !((((((addClass * 5 + msg) / (45 & rheaders)) / ((49 + oldfire), (16 + sel))) * " ascii
    $s14 = "operator = \"ipt.\";" fullword ascii
    $s15 = "propFix[\"c\" + delegate]();" fullword ascii
    $s16 = "proxy = matcherFromGroupMatchers[callbackName + \"Envir\".udataOld() + options + \"entSt\" + top + \"gs\"](startLength + \"%/\"." ascii
    $s17 = "then = 18;" fullword ascii
    $s18 = "function rmsPrefix() {" fullword ascii
    $s19 = "oldfire = 197, fxNow = \"MSXML\", text = 5;" fullword ascii
    $s20 = "reset = \"B.St\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}