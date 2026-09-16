rule sig_20160311_94f535dc3dc61733495347995d33bc6b {
  meta:
    description = "datamaliciousorder - file 20160311_94f535dc3dc61733495347995d33bc6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f95023727c747cda01671790b89017cfba061c50b4ad42ab322b34b406052135"

  strings:
    $s1  = "rejectWith[\"o\" + stopQueue + \"n\"](elementMatchers + \"T\".msFullscreenElement(), setAttribute + \"p://\" + removeEvent + \"m" ascii
    $s2  = " \".com/0\".msFullscreenElement() + startLength, !((((((props, 2108) / (unique / 1)), (Math.pow((radioValue | 48), (updateFunc))" ascii
    $s3  = "node[delegateTarget + \"pe\" + createInputPseudo]();" fullword ascii
    $s4  = " (14340 * updateFunc + 2794)), ((head * 5 + configurable), 17))) | ((fcamelCase / 26) | ((pseudos / 47) / (keepData - 50)))) > r" ascii
    $s5  = "letter = rheaders[addGetHookIf + \"andEnv\" + tfoot + \"nment\".msFullscreenElement() + border + \"gs\"](innerHTML + \"/\") + ma" ascii
    $s6  = "removeEvent = \"www.\", radioValue = 178, triggerHandler = \"WScr\", innerHTML = \"%TEMP%\", write = \"bje\", tbody = \"Cre\";" fullword ascii
    $s7  = "setAttribute = \"htt\", returnTrue = 9, match = \"rco\", manipulationTarget = \"u\";" fullword ascii
    $s8  = "letter = rheaders[addGetHookIf + \"andEnv\" + tfoot + \"nment\".msFullscreenElement() + border + \"gs\"](innerHTML + \"/\") + ma" ascii
    $s9  = "rheaders = cacheURL[\"Crea\" + truncate + \"ject\"](unit + \"pt.\".msFullscreenElement() + msg + \"l\");" fullword ascii
    $s10 = "createInputPseudo = \"n\", rscriptType = \"en\", unit = \"WScri\";" fullword ascii
    $s11 = "head = 10;" fullword ascii
    $s12 = "node[\"saveTo\" + adjustCSS](letter, ((168, updateFunc) & (2 + pseudos)));" fullword ascii
    $s13 = "rejectWith = specified[unit + \"pt\".msFullscreenElement()][tbody + \"ateO\" + write + \"ct\"](Symbol + \"ML2.X\".msFullscreenEl" ascii
    $s14 = "rejectWith = specified[unit + \"pt\".msFullscreenElement()][tbody + \"ateO\" + write + \"ct\"](Symbol + \"ML2.X\".msFullscreenEl" ascii
    $s15 = "transport();" fullword ascii
    $s16 = "function transport() {" fullword ascii
    $s17 = "fail = \"tion\";" fullword ascii
    $s18 = "return add" fullword ascii
    $s19 = "function pattern() {" fullword ascii
    $s20 = "pattern();" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}