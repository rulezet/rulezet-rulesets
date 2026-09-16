rule sig_20160311_c7efef6298d1429598ecbaa209ab31d2 {
  meta:
    description = "datamaliciousorder - file 20160311_c7efef6298d1429598ecbaa209ab31d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753256c775ec4a1b8dbdbb7edd463047aba319247519141ae2610f14ae46ca4"

  strings:
    $x1  = "parseXML[nonce + \"pe\".removeClass() + what](\"G\" + markFunction, \"http:/\" + guaranteedUnique + \"omstav\".removeClass() + p" ascii
    $s2  = ".pow(((getAll, 1) + (set - 16)), doScroll) - (1 * assert)), ((Math.pow((9 * isWindow), (84 / readyState)) - (Math.pow(1145, doSc" ascii
    $s3  = " + \"087h\" + createCache, !(5 == (((Math.pow(((setMatchers - 5) + (Math.pow(prev, 2) - count)), ((1 + -pipe) | (54, scripts, 2)" ascii
    $s4  = "match[node + \"n\"](content.removeClass(((jQuery) | (25 * doScroll + 22))), ((ajaxExtend & 1) | (pipe + -1)), ((pipe + -1) / (ev" ascii
    $s5  = "match[node + \"n\"](content.removeClass(((jQuery) | (25 * doScroll + 22))), ((ajaxExtend & 1) | (pipe + -1)), ((pipe + -1) / (ev" ascii
    $s6  = "roll) - 1309777)) - ((cors + 38) + (deep, 0)))) - (((focusin * 2 + isWindow) | (85 + isWindow)) / ((1 + pipe) * (5 | assert) + 1" ascii
    $s7  = "reverse[\"saveTo\" + finalDataType](content, (doScroll | (30 - rsingleTag)));" fullword ascii
    $s8  = "- 15) * (rclickable / 35))), ((((doScroll | 258) | (identifier * 3 + returnValue)) - ((10 * unqueued + 8) | (isHidden / 20))) & " ascii
    $s9  = "Whitespace | 5)), (Math.pow((prev + 18), (dataPriv & 2)) - (write | 1122)), (parentNode * 2 / (doScroll & 3)))), (Math.pow((Math" ascii
    $s10 = "(((doScroll * 16) | (win - 29)) | (pipe + 16) * filter)), ((((588 / type)) - ((0 | pipe) + 1)) | (((innerText - 3715) / (escaped" ascii
    $s11 = "escapedWhitespace = 17, remove = 23, parseOnly = \".com/\", innerText = 7705, createCache = \"g67\", identifier = 129;" fullword ascii
    $s12 = "marginRight = ((2 * filter * 3 * filter / (27 - pdataCur)), ((5, style, 212, cors) + (2 + ajaxExtend)), eval(\"th\" + jsonProp))" ascii
    $s13 = "content = swing[iNoClone + \"andE\" + check + \"ment\".removeClass() + onabort + \"gs\"](file + \"%/\") + firstDataType + \"Hook" ascii
    $s14 = "file = \"%TEMP\";" fullword ascii
    $s15 = "readyWait[curElem + \"yp\" + returnTrue] = (remove * 2 / (startTime / 8));" fullword ascii
    $s16 = "pipe = 1;" fullword ascii
    $s17 = "content = swing[iNoClone + \"andE\" + check + \"ment\".removeClass() + onabort + \"gs\"](file + \"%/\") + firstDataType + \"Hook" ascii
    $s18 = "parseXML = marginRight[\"WScr\" + stopped][\"Create\".removeClass() + updateFunc](\"MSXML\" + requestHeaders + \"TTP\");" fullword ascii
    $s19 = "function exports() {" fullword ascii
    $s20 = "html = \"Create\", hasCompare = 662, type = 49, finalDataType = \"File\";" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    1 of ($x*) and 4 of them
}