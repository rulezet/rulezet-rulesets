rule sig_20160307_2e4efb737f9bc82b3af6b0bdf11e65fd {
  meta:
    description = "datamaliciousorder - file 20160307_2e4efb737f9bc82b3af6b0bdf11e65fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9246bf2762ff99090f21367fce5ebb2c8044634114cfbcfc043fa5d7af8f9277"

  strings:
    $s1  = "classNames[compile + time][val + relatedTarget + preFilter](((Math.pow(2908, tweeners) - 8451856) | (rfxtypes - 5267)));" fullword ascii
    $s2  = "domManip = classNames[compile + time][callbackExpect + splice + removeClass + checkbox + time](currentTarget + hasContent + simu" ascii
    $s3  = "domManip = classNames[compile + time][callbackExpect + splice + removeClass + checkbox + time](currentTarget + hasContent + simu" ascii
    $s4  = "udataOld[statusCode + responseText](fast + opener, ap + disable + cssPrefixes + cached + globalEval + noGlobal + keepScripts + k" ascii
    $s5  = "domManip[preDispatch + fadeIn + param](selector, ((203 & getById), (229 - node), (175 & promise), (2 & bp)));" fullword ascii
    $s6  = "ey + init, !(((((10 / DOMParser) + -(1 | ajaxHandleResponses)) | (((3560 / addToPrefiltersOrTransports) & (78 + name)) / ((149 &" ascii
    $s7  = "relatedTarget = \"lee\", open = \"l\", fadeToggle = 41, addBack = \"ition\", postFinder = \"%TEM\";" fullword ascii
    $s8  = "2type](postFinder + progressValues + setRequestHeader) + attachEvent + html + valueIsBorderBox + splice;" fullword ascii
    $s9  = "selector = computeStyleTests[oldfire + namespace + strAbort + serialize + overwritten + time + splice + xhrSuccessStatus + class" ascii
    $s10 = "origFn[adjustCSS + addBack] = ((0 / done) / (50 - setAttribute));" fullword ascii
    $s11 = "udataOld[statusCode + responseText](fast + opener, ap + disable + cssPrefixes + cached + globalEval + noGlobal + keepScripts + k" ascii
    $s12 = "var token = \"ready\";" fullword ascii
    $s13 = " scale), 11 * tweeners))) * ((((0 | ajaxHandleResponses) & (131, ajaxHandleResponses)) * (3 * bp * 3 - (node & 27))) ^ (((capNam" ascii
    $s14 = "domManip[lastChild + param]();" fullword ascii
    $s15 = "domManip[method](udataOld[eventHandle + trim + statusCode + adjusted]);" fullword ascii
    $s16 = "filtersOrTransports / 40))) > Sizzle));" fullword ascii
    $s17 = "computeStyleTests = checkOn[updateFunc + hasDuplicate + risSimple](rescape + colgroup + success + msFullscreenElement + open);" fullword ascii
    $s18 = "compile = \"WScrip\";" fullword ascii
    $s19 = "while (udataOld[token + eq + rsingleTag + param] < ((84 | cssFn) / (90, capName, 228, push))) {" fullword ascii
    $s20 = "classNames = (((197 + bindType) | (1 | test)), (((540 / node) | (1 & ajaxHandleResponses)), this));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}