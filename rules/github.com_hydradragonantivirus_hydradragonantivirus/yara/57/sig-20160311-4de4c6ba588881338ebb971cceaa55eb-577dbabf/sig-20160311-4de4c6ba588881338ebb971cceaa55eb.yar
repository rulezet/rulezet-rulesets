rule sig_20160311_4de4c6ba588881338ebb971cceaa55eb {
  meta:
    description = "datamaliciousorder - file 20160311_4de4c6ba588881338ebb971cceaa55eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3fb830e1ea150e7546c01e31237c7107a73566bbab3f758336bc2dcd159829"

  strings:
    $s1  = "ajaxHandleResponses = parseOnly[\"Expan\" + getElementById + \"ronme\".adjustCSS() + expando + \"ring\" + xhrSupported](\"%TEMP%" ascii
    $s2  = "ajaxHandleResponses = parseOnly[\"Expan\" + getElementById + \"ronme\".adjustCSS() + expando + \"ring\" + xhrSupported](\"%TEMP%" ascii
    $s3  = "preFilters[fnOver + \"en\"](ajaxConvert + \"T\", parentOffset + \"//pe\".adjustCSS() + getResponseHeader + \"alice.\" + hasFocus" ascii
    $s4  = "), 61 * attaches, 2 * params, 1))) | ((((aup - 145), (currentTime / 6)) | (Math.pow((register | 41), (attaches & 3)) - (identifi" ascii
    $s5  = "onseContainer / 47)) - ((Math.pow(ap, 2) - funcName) | (31 * attaches + 29))), (((subordinate / 43) - (clientX | 13)) + ((params" ascii
    $s6  = "hide = (((3255 / slideToggle) - (3 | bindType)), (2 + (register & 4)), eval(\"t\" + dataShow + \"s\".adjustCSS()));" fullword ascii
    $s7  = ", 238, special, 12) - (currentTime | 8)));" fullword ascii
    $s8  = "preFilters = hide[linear + \"ript\".adjustCSS()][curLeft + \"eOb\" + has](\"MSX\" + preexisting + \"LHTTP\".adjustCSS());" fullword ascii
    $s9  = "parseOnly = func[cssNormalTransform + \"teO\" + Data + \"t\".adjustCSS()](cssShow + \"t.She\" + pdataCur);" fullword ascii
    $s10 = "oMatchesSelector = hide[linear + \"ript\".adjustCSS()][proxy + \"Obj\" + leadingRelative](\"ADODB\" + prependTo + \"ream\".adjus" ascii
    $s11 = "classes[\"R\".adjustCSS() + fireGlobals](ajaxHandleResponses.adjustCSS((mozMatchesSelector & 95)), (capName / 8), ((rlocalProtoc" ascii
    $s12 = "\" + rbuggyQSA + \"pl/0\".adjustCSS() + stopQueue + \"5\", !(((((xhrFields * 3 * xhrFields * 3 * xhrFields, 13 * xhrFields * 5, " ascii
    $s13 = "oMatchesSelector[checkClone + \"pe\" + swing]();" fullword ascii
    $s14 = "func = hide[iNoClone + \"pt\"];" fullword ascii
    $s15 = "aup = 319, hasFocus = \"rep\", Data = \"bjec\", pdataOld = 42, xhrSupported = \"s\", toSelector = \"l\";" fullword ascii
    $s16 = "classes[\"R\".adjustCSS() + fireGlobals](ajaxHandleResponses.adjustCSS((mozMatchesSelector & 95)), (capName / 8), ((rlocalProtoc" ascii
    $s17 = "docElem = \"e\", register = 4, clearQueue = \"se\", proxy = \"Create\";" fullword ascii
    $s18 = "identifier = 31424;" fullword ascii
    $s19 = "function responses() {" fullword ascii
    $s20 = "function statusText() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}