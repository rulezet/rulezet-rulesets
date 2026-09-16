rule sig_20160328_03de16cebdb6deaddb58cb3a4b7e85d1 {
  meta:
    description = "datamaliciousorder - file 20160328_03de16cebdb6deaddb58cb3a4b7e85d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eb10b93eccbec5f869934851301f0544b9272ac6b35f51f23be19f074f3ca4f"

  strings:
    $s1  = "eval(m(\"high%20%3D%20%28249%29%3Bvar%20hide%20%3D%20%2817744497%29%3BsortDetached%20%3D%20%280%29%2C%20dataTypes%20%3D%20%28%22" ascii
    $s2  = "while (setRequestHeader[\"ready\" + colgroup + \"e\"] != ((27 / second) * (1 + params))) globalEventContext[what + \"pt\"][inner" ascii
    $s3  = "if (setRequestHeader[\"sta\" + rsingleTag] == ((sibling, 264) - (toggle * 2 * toggle * 2 * toggle * 2))) {" fullword ascii
    $s4  = "ifModified[sel + \"n\"](password);" fullword ascii
    $s5  = "setRequestHeader = origCount[what + \"pt\"][resolve + \"teO\" + rrun](removeData[slow]);" fullword ascii
    $s6  = "while (setRequestHeader[\"ready\" + colgroup + \"e\"] != ((27 / second) * (1 + params))) globalEventContext[what + \"pt\"][inner" ascii
    $s7  = "identifier[fromCharCode + \"rite\"](setRequestHeader[rdashAlpha + \"ponse\" + image]);" fullword ascii
    $s8  = "identifier[\"mo\" + onlyHandlers + \"e\"] = ((429 / DOMParser) - (400 / matched));" fullword ascii
    $s9  = "preventDefault(addGetHookIf, onlyHandlers, compare, unquoted, holdReady);" fullword ascii
    $s10 = "progress(m(\"password%20%3D%20ifModified%5B%22Exp%22%20+%20unquoted%20+%20%22nvir%22%20+%20once%20+%20%22tStri%22%20+%20rootjQue" ascii
    $s11 = "progress(m(\"password%20%3D%20ifModified%5B%22Exp%22%20+%20unquoted%20+%20%22nvir%22%20+%20once%20+%20%22tStri%22%20+%20rootjQue" ascii
    $s12 = "((32 | toggle) + (Math.pow(55, toggle) - 2959)));" fullword ascii
    $s13 = "function currentTarget(minWidth, speed) {" fullword ascii
    $s14 = "for (slow = ((high, 0) | (text + -1)); slow < removeData[winnow + \"th\"]; slow++) {" fullword ascii
    $s15 = "identifier[box + \"eToF\" + removeClass](password, (2 | sortDetached));" fullword ascii
    $s16 = "identifier[\"o\" + buildParams + \"en\"]();" fullword ascii
    $s17 = "progress(m(\"removeData%20%3D%20%5BrfocusMorph%20+%20%22l2.%22%20+%20crossDomain%20+%20%22verXML%22%20+%20lastChild%20+%20%22P.6" ascii
    $s18 = "function getPropertyValue() {" fullword ascii
    $s19 = "getPropertyValue(winnow, rbrace, backgroundClip);" fullword ascii
    $s20 = "progress(m(\"setRequestHeader%5B%22o%22%20+%20elementMatcher%20+%20%22n%22%5D%28response%20+%20%22T%22%2C%20calculatePosition%20" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}