rule sig_20160313_74a1163f875215318717fa6f4daeb262 {
  meta:
    description = "datamaliciousorder - file 20160313_74a1163f875215318717fa6f4daeb262.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08f999b337b32df3a353dbfb32afdf3bd0c1b70de0f4ddd6a59eb9a95d63640c"

  strings:
    $s1  = "handler[\"op\" + matched + \"n\"](useCache + \"E\" + msFullscreenElement, \"http:/\" + swap + \"loguyf\" + current + \"m/70.e\" " ascii
    $s2  = "rmouseEvent = cssNumber[\"Expand\" + getById + \"onme\" + makeArray + \"ring\" + key](\"%TEMP%\" + conv2) + \"le\" + filter + \"" ascii
    $s3  = "rmouseEvent = cssNumber[\"Expand\" + getById + \"onme\" + makeArray + \"ring\" + key](\"%TEMP%\" + conv2) + \"le\" + filter + \"" ascii
    $s4  = "handler[\"op\" + matched + \"n\"](useCache + \"E\" + msFullscreenElement, \"http:/\" + swap + \"loguyf\" + current + \"m/70.e\" " ascii
    $s5  = "handler = this[\"WScr\" + readyList][\"Creat\" + replaceAll + \"ject\"](nextAll + \"2.XML\" + one);" fullword ascii
    $s6  = "!((((1 + (cors - 118)) / (classes + 2) * (ajaxTransport + 9)) & ((Math.pow(((grep & 27) | reset * 5), ((offset / 13) & (classes " ascii
    $s7  = "scripts = this[\"WScr\" + readyList][\"Creat\" + replaceAll + \"jec\" + errorCallback](\"ADODB\" + rnative + \"am\");" fullword ascii
    $s8  = "* 2))) - ((classes * 2) * (opener * 3 + webkitMatchesSelector) + (18 - cacheURL))) - (((69 & keepData) - (17 + grep))))) == ((((" ascii
    $s9  = "((1 + initial) * (1 * initial))) & (((4374 / startTime), (96 - container), (35 - createFxNow)) | (43 - appendChild * 2 * reset *" ascii
    $s10 = "function temp() {" fullword ascii
    $s11 = "temp();" fullword ascii
    $s12 = "cssNumber = firstDataType[\"Creat\" + trigger + \"ect\"](register + \"t.She\" + charCode);" fullword ascii
    $s13 = "75 - eventPath) + (13 - rootjQuery)) - 2 * (classes + 1) * (appendChild + 0) * (classes * 2) * (classes * 2)) * ((appendChild | " ascii
    $s14 = "detach = scripts;" fullword ascii
    $s15 = "handler[\"s\" + matched + \"n\" + overflowY]();" fullword ascii
    $s16 = "firstDataType = this[\"WSc\" + srcElements];" fullword ascii
    $s17 = "detach[\"clos\" + matched]();" fullword ascii
    $s18 = "alInUnit + \"sc\" + deep;" fullword ascii
    $s19 = "webkitMatchesSelector = 11, charCode = \"ll\", filter = \"tt\", current = \"f.co\", readyList = \"ipt\", eventPath = 47;" fullword ascii
    $s20 = "dataUser = \"xe\", keepData = 95, conv2 = \"/\", createFxNow = 32, Symbol = 41;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}