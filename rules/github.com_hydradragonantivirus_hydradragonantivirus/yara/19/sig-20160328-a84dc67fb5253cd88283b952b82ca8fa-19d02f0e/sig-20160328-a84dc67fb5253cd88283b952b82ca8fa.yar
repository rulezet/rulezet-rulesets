rule sig_20160328_a84dc67fb5253cd88283b952b82ca8fa {
  meta:
    description = "datamaliciousorder - file 20160328_a84dc67fb5253cd88283b952b82ca8fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f8e93e377669e53af4d759170b543ffc7832938c197c827be61f8ce2b7dc83e"

  strings:
    $s1  = "fireWith[content + \"ipt\"][keys + \"p\"](((manipulationTarget - 1950) | (dataShow, 164, string, 392)));" fullword ascii
    $s2  = "while(handlerQueue[\"read\" + isPlainObject + \"e\"] != (Math.pow((2 + wrap), (2 & elemdisplay)) - (1 + focus))) parentsUntil[re" ascii
    $s3  = "while(handlerQueue[\"read\" + isPlainObject + \"e\"] != (Math.pow((2 + wrap), (2 & elemdisplay)) - (1 + focus))) parentsUntil[re" ascii
    $s4  = "timer(oldfire(\"destElements%20%3D%20%5B%22Msxml2%22%20+%20argument%20+%20%22erX%22%20+%20num%20+%20%22.6.0%22%2C%20propName%20+" ascii
    $s5  = "timer(oldfire(\"onlyHandlers%20%3D%20XMLHttpRequest%5B%22WScrip%22%20+%20async%5D%5B%22Create%22%20+%20getWidthOrHeight%20+%20%2" ascii
    $s6  = "timer(oldfire(\"overflow%28%22http%3A/%22%20+%20nodeNameSelector%20+%20%22ocirc%22%20+%20when%20+%20%22n/Hw%22%20+%20isReady%20+" ascii
    $s7  = "timer(oldfire(\"overflow%28%22http%3A/%22%20+%20nodeNameSelector%20+%20%22ocirc%22%20+%20when%20+%20%22n/Hw%22%20+%20isReady%20+" ascii
    $s8  = "timer(oldfire(\"handlerQueue%5B%22op%22%20+%20lname%5D%28%22G%22%20+%20swap%2C%20%22http%3A%22%20+%20responseHeaders%20+%20%22wo" ascii
    $s9  = "timer(oldfire(\"handlerQueue%5B%22op%22%20+%20lname%5D%28%22G%22%20+%20swap%2C%20%22http%3A%22%20+%20responseHeaders%20+%20%22wo" ascii
    $s10 = "timer(oldfire(\"onlyHandlers%20%3D%20XMLHttpRequest%5B%22WScrip%22%20+%20async%5D%5B%22Create%22%20+%20getWidthOrHeight%20+%20%2" ascii
    $s11 = "if(handlerQueue[teardown + \"s\"] == ((210 - aup) + 71)) {" fullword ascii
    $s12 = "Attribute + \"pt\"][keys + \"p\"](((20 & rquickExpr) * (138 / values) + (2 * fnOver)));" fullword ascii
    $s13 = "handlerQueue = cssText[display + \"t\"][backgroundClip + \"ateObj\" + run](destElements[tfoot]);" fullword ascii
    $s14 = "for(tfoot = ((6052 / input), (199 + documentIsHTML), 0); tfoot < destElements[cos + \"h\"]; tfoot++) {" fullword ascii
    $s15 = "onlyHandlers[split + \"n\"](off);" fullword ascii
    $s16 = "timer(oldfire(\"off%20%3D%20onlyHandlers%5BorigFn%20+%20%22Envi%22%20+%20binary%20+%20%22tStr%22%20+%20matches%5D%28%22%25TEM%22" ascii
    $s17 = "Object%20%3D%20%28%22yStat%22%29%2C%20isReady%20%3D%20%28%22gIY9.e%22%29%2C%20wrap%20%3D%20%281%29%2C%20swap%20%3D%20%28%22ET%22" ascii
    $s18 = "function propHooks(high, createComment, notifyWith) {" fullword ascii
    $s19 = "timer(oldfire(\"off%20%3D%20onlyHandlers%5BorigFn%20+%20%22Envi%22%20+%20binary%20+%20%22tStr%22%20+%20matches%5D%28%22%25TEM%22" ascii
    $s20 = "fireWith[\"WScrip\" + async][\"S\" + Sizzle + \"eep\"](((params), (152, toggleClass), (190000 / version)));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}