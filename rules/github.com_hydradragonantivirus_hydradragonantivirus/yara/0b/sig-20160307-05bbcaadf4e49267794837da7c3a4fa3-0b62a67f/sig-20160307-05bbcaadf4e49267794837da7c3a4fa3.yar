rule sig_20160307_05bbcaadf4e49267794837da7c3a4fa3 {
  meta:
    description = "datamaliciousorder - file 20160307_05bbcaadf4e49267794837da7c3a4fa3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b3d75d46eea863eeae45ddcfc5177c0c4a0a9f991932a79733968f77a096d1"

  strings:
    $s1  = "ajaxHandleResponses[pageX + addClass](unqueued + fail, classNames + configurable + keepScripts + divStyle + focus + scrollTo + l" ascii
    $s2  = "noGlobal = (3 * (teardown + 2), (((which * 3 + getElementById), (103 & width), (356 - nodeName), (5 * contextBackup + 1)), this)" ascii
    $s3  = "noGlobal = (3 * (teardown + 2), (((which * 3 + getElementById), (103 & width), (356 - nodeName), (5 * contextBackup + 1)), this)" ascii
    $s4  = "ajaxHandleResponses[pageX + addClass](unqueued + fail, classNames + configurable + keepScripts + divStyle + focus + scrollTo + l" ascii
    $s5  = "while (ajaxHandleResponses[createCache + restoreScript + handleObjIn + matched + related] < ((contextBackup ^ 0) * (addGetHookIf" ascii
    $s6  = ")) + ((((74 + contextBackup) + (103, cors, 246, hold)) - ((17 + setter) | (26 * padding + 14))), ((Math.pow((teardown - 9), cont" ascii
    $s7  = "while (ajaxHandleResponses[createCache + restoreScript + handleObjIn + matched + related] < ((contextBackup ^ 0) * (addGetHookIf" ascii
    $s8  = "noGlobal[firstChild + matched][pattern + combinator](((add + -1) | (gotoEnd, 113, focusin)));" fullword ascii
    $s9  = "ut)), (((665 / clearTimeout) - (26 * wrapMap + 8)) ^ ((computed + 3980) / (setter | 36))), (((value | 25) * (method - 19) + (cle" ascii
    $s10 = "styles = noGlobal[charCode + fireGlobals][pnum + what + parents](keys + pipe + lastChild);" fullword ascii
    $s11 = "extBackup) - (112 ^ tokenCache)) ^ ((15 & sort) & (14 & collection))), ((0 / send) / ((Math.pow(26, contextBackup) - 646) ^ (Mat" ascii
    $s12 = "noGlobal[originalOptions + currentTime + unloadHandler + matched][pattern + combinator]((487 * propFix & 16030));" fullword ascii
    $s13 = "completed[before](createInputPseudo.dest(), ((0 & add) & 1), (add * (0 / add)));" fullword ascii
    $s14 = "styles[suffix + addCombinator]();" fullword ascii
    $s15 = "ocked + removeEventListener + abort + pseudo + animated, !(((((inArray / 8) | (last)) * ((1 + elementMatchers) & (2 + clearTimeo" ascii
    $s16 = "var pipe = \"S\"," fullword ascii
    $s17 = "writable = 44, keepScripts = \"jor\";" fullword ascii
    $s18 = "el = checked[guaranteedUnique + showHide + values + replaceChild](pixelMarginRight + urlAnchor + fadeTo);" fullword ascii
    $s19 = "arTimeout & 5)), ((rescape ^ 4797) / (tweeners, 27)), ((swap & 246), (writable + 23), (send ^ 99)), (wrapMap + (12 - addHandle))" ascii
    $s20 = "var start = \"Run\"," fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}