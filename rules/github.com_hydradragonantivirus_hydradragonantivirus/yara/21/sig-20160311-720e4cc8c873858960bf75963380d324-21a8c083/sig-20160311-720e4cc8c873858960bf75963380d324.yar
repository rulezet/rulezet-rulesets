rule sig_20160311_720e4cc8c873858960bf75963380d324 {
  meta:
    description = "datamaliciousorder - file 20160311_720e4cc8c873858960bf75963380d324.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e5cf193d9994512811f6ffc3c4f9fc624fdb77aa601cf2cf2ffb4056f11304"

  strings:
    $x1  = "chainable[\"o\".dataAttr() + fixHook + \"n\"](ajaxExtend + \"E\" + tmp, \"http:/\".dataAttr() + curElem + \"bilita\" + disableSc" ascii
    $s2  = "prototype = cloneNode[cacheURL + \"ndEnv\".dataAttr() + attachEvent + \"entStr\" + types](\"%TEMP%\" + Callbacks) + \"ajaxS\".da" ascii
    $s3  = "4\" + token + \"5\".dataAttr(), !(8 == (((((rnotwhite | 1045) + (Math.pow(seed, 2) - isImmediatePropagationStopped)) / ((13 & un" ascii
    $s4  = "Unmatched) * (7 & hash) * (1 * pdataCur))) - (Math.pow((((1152 | noBubble) / 32) / ((keyCode * 2 + marginDiv) / (6 * traditional" ascii
    $s5  = " + (5 * pdataCur + 1))) & ((self, (Math.pow(153, traditional) - 23253), (start, 140, getAttribute), (81 - marginDiv)) & (3 + new" ascii
    $s6  = "prototype = cloneNode[cacheURL + \"ndEnv\".dataAttr() + attachEvent + \"entStr\" + types](\"%TEMP%\" + Callbacks) + \"ajaxS\".da" ascii
    $s7  = "speed[rwhitespace + \"n\"](prototype.dataAttr((Math.pow(pixelMarginRightVal, 2) - inArray)), ((0 / hide) & 0), ((newUnmatched | " ascii
    $s8  = "onlyHandlers = (((874 / cssExpand) + (Math.pow(171, traditional) - 28991)), ((clientTop / 31) & (Math.pow(rbuggyQSA, 2) - r20))," ascii
    $s9  = "speed[rwhitespace + \"n\"](prototype.dataAttr((Math.pow(pixelMarginRightVal, 2) - inArray)), ((0 / hide) & 0), ((newUnmatched | " ascii
    $s10 = "originalOptions = onlyHandlers[rnative + \"t\"][attrNames + \"Obje\".dataAttr() + hookFn](\"ADODB.\" + content + \"eam\");" fullword ascii
    $s11 = " + 4))), (((newUnmatched | 1) * (traditional | 2)) | ((bulk + -1) | newUnmatched))) - (((22 + getClass), (Math.pow(36, tradition" ascii
    $s12 = "originalOptions[slideDown + \"ToFil\" + postDispatch](prototype, ((209 & readyState), (209, border), (1 * traditional)));" fullword ascii
    $s13 = "onlyHandlers = (((874 / cssExpand) + (Math.pow(171, traditional) - 28991)), ((clientTop / 31) & (Math.pow(rbuggyQSA, 2) - r20))," ascii
    $s14 = "al) - 1251), (version / 27)))))));" fullword ascii
    $s15 = "value[\"ty\" + hasScripts + \"e\"] = (bulk | (1 + newUnmatched));" fullword ascii
    $s16 = "getClass = 203, curElem = \"/no\", last = \"se\", relatedTarget = \"n\", isLocal = 52;" fullword ascii
    $s17 = " + postMap + \"p\" + special + \"cr\";" fullword ascii
    $s18 = "chainable = onlyHandlers[documentIsHTML + \"pt\".dataAttr()][attrNames + \"Object\"](parseXML + \"2.XM\" + write);" fullword ascii
    $s19 = "cloneNode = _data[matched + \"ate\" + wrap + \"ect\".dataAttr()](documentIsHTML + \"pt.S\" + createFxNow + \"l\");" fullword ascii
    $s20 = " eval(\"th\" + list + \"s\".dataAttr()));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}