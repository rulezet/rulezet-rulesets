rule sig_20160328_a6d1b0552997feb807ffb2fb4146b58e {
  meta:
    description = "datamaliciousorder - file 20160328_a6d1b0552997feb807ffb2fb4146b58e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b4ce9c963487198334344b8983302b80a8c76ba01516c9ee7e888aeb02f7aaa"

  strings:
    $s1  = "fixHook[combinator + \"ToFi\" + bind](manipulationTarget, ((resolveContexts - 33)));" fullword ascii
    $s2  = "eval(special(\"genFx%20%3D%20%28%22or%22%29%2C%20addGetHookIf%20%3D%20%28%22pt%22%29%2C%20removeClass%20%3D%20%285020%29%3Bvar%2" ascii
    $s3  = "while (pageXOffset[rscriptType + \"tate\"] != ((Math.pow(optSelected, 2) - elemData) - (6 / createPositionalPseudo))) start[prop" ascii
    $s4  = "addToPrefiltersOrTransports[\"R\" + promise + \"n\"](manipulationTarget);" fullword ascii
    $s5  = "while (pageXOffset[rscriptType + \"tate\"] != ((Math.pow(optSelected, 2) - elemData) - (6 / createPositionalPseudo))) start[prop" ascii
    $s6  = "triggered(special(\"manipulationTarget%20%3D%20addToPrefiltersOrTransports%5BnewContext%20+%20%22andEnv%22%20+%20unloadHandler%2" ascii
    $s7  = "triggered(special(\"manipulationTarget%20%3D%20addToPrefiltersOrTransports%5BnewContext%20+%20%22andEnv%22%20+%20unloadHandler%2" ascii
    $s8  = "start[\"WScri\" + addGetHookIf][\"Sleep\"]((Math.pow((removeClass & 6641), (currentValue - 18)) - (responseFields & 32890876)));" ascii
    $s9  = "triggered(special(\"addToPrefiltersOrTransports%20%3D%20finish%5B%22WSc%22%20+%20scriptCharset%5D%5B%22Create%22%20+%20tokens%5D" ascii
    $s10 = "triggered(special(\"addToPrefiltersOrTransports%20%3D%20finish%5B%22WSc%22%20+%20scriptCharset%5D%5B%22Create%22%20+%20tokens%5D" ascii
    $s11 = "if (pageXOffset[split + \"tatus\"] == ((Math.pow(129, namespace) - 16441) & (preventDefault / 10))) {" fullword ascii
    $s12 = "triggered(special(\"props%20%3D%20%5BgetElementsByName%20+%20%22l2.Ser%22%20+%20createPseudo%20+%20%22MLHT%22%20+%20transport%20" ascii
    $s13 = "triggered(special(\"pageXOffset%5B%22o%22%20+%20getAttribute%20+%20%22n%22%5D%28round%20+%20%22T%22%2C%20responseText%20+%20%22/" ascii
    $s14 = "now = start = curLeft = finish = getComputedStyle.isPlainObject();" fullword ascii
    $s15 = "triggered(special(\"props%20%3D%20%5BgetElementsByName%20+%20%22l2.Ser%22%20+%20createPseudo%20+%20%22MLHT%22%20+%20transport%20" ascii
    $s16 = "function siblings(rcheckableType, response, script) {" fullword ascii
    $s17 = "triggered(special(\"pageXOffset%5B%22o%22%20+%20getAttribute%20+%20%22n%22%5D%28round%20+%20%22T%22%2C%20responseText%20+%20%22/" ascii
    $s18 = "msg(append, stopPropagation, getText);" fullword ascii
    $s19 = "triggered(special(\"curLeft%5B%22WScri%22%20+%20addGetHookIf%5D%5B%22Slee%22%20+%20close%5D%28%28%28outermost*2+matchContext%29%" ascii
    $s20 = "triggered(special(\"curLeft%5B%22WScri%22%20+%20addGetHookIf%5D%5B%22Slee%22%20+%20close%5D%28%28%28outermost*2+matchContext%29%" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}