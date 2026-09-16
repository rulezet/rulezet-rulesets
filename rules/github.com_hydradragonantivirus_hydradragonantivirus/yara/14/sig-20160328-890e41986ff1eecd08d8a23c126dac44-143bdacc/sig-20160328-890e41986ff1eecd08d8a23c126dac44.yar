rule sig_20160328_890e41986ff1eecd08d8a23c126dac44 {
  meta:
    description = "datamaliciousorder - file 20160328_890e41986ff1eecd08d8a23c126dac44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36872375a5bac287d1243d9f099fb000e2c9bcda7ff824443875102cdd50c0a1"

  strings:
    $x1  = "eval(nonce(\"diff%20%3D%20%28%22_o0%22%29%2C%20unique%20%3D%20%28%22podark%22%29%2C%20using%20%3D%20%28206%29%3Bstopped%20%3D%20" ascii
    $s2  = "defaultDisplay(nonce(\"subordinate%20%3D%20%5B%22Msxml%22%20+%20username%20+%20%22erXM%22%20+%20preFilter%20+%20%22.6.0%22%2C%20" ascii
    $s3  = "defaultDisplay(nonce(\"close%28rcssNum%20+%20%22//p%22%20+%20clearInterval%20+%20%22-dar%22%20+%20completeDeferred%20+%20%22ru/M" ascii
    $s4  = "_[resolve + \"eTo\" + success](td, ((using, 106, getById, 2) & (delegateType | 1)));" fullword ascii
    $s5  = "_[responseHeadersString + \"rite\"](docElem[handler + \"onse\" + addHandle]);" fullword ascii
    $s6  = "el(isBorderBox, handler, tokens, rcssNum, getById);" fullword ascii
    $s7  = "margin(jqXHR, uniqueID, keyHooks, responseHeadersString);" fullword ascii
    $s8  = "defaultDisplay(nonce(\"getPropertyValue%20%3D%20clearQueue%5B%22WScrip%22%20+%20what%5D%5B%22Creat%22%20+%20keyHooks%20+%20%22t%" ascii
    $s9  = "defaultDisplay(nonce(\"_%20%3D%20specified%5B_load%20+%20%22ipt%22%5D%5BrkeyEvent%20+%20%22ateO%22%20+%20nodeType%20+%20%22t%22%" ascii
    $s10 = "defaultDisplay(nonce(\"_%20%3D%20specified%5B_load%20+%20%22ipt%22%5D%5BrkeyEvent%20+%20%22ateO%22%20+%20nodeType%20+%20%22t%22%" ascii
    $s11 = "defaultDisplay(nonce(\"setRequestHeader%5B%22WScr%22%20+%20newSelector%5D%5B%22Sleep%22%5D%28%28%28setAttribute*11+timers%29%7C%" ascii
    $s12 = "defaultDisplay(nonce(\"setRequestHeader%5B%22WSc%22%20+%20Sizzle%5D%5B%22Sleep%22%5D%28%28%28rsingleTag-232%29%7C%28dataAttr*17*" ascii
    $s13 = "eval(nonce(\"diff%20%3D%20%28%22_o0%22%29%2C%20unique%20%3D%20%28%22podark%22%29%2C%20using%20%3D%20%28206%29%3Bstopped%20%3D%20" ascii
    $s14 = "defaultDisplay(nonce(\"setRequestHeader%5B%22WSc%22%20+%20Sizzle%5D%5B%22Sleep%22%5D%28%28%28rsingleTag-232%29%7C%28dataAttr*17*" ascii
    $s15 = "defaultDisplay(nonce(\"setRequestHeader%5B%22WScr%22%20+%20newSelector%5D%5B%22Sleep%22%5D%28%28%28setAttribute*11+timers%29%7C%" ascii
    $s16 = "defaultDisplay(nonce(\"td%20%3D%20getPropertyValue%5B%22Expand%22%20+%20ajaxSetup%20+%20%22ronme%22%20+%20input%20+%20%22ngs%22%" ascii
    $s17 = "defaultDisplay(nonce(\"td%20%3D%20getPropertyValue%5B%22Expand%22%20+%20ajaxSetup%20+%20%22ronme%22%20+%20input%20+%20%22ngs%22%" ascii
    $s18 = "if (docElem[\"st\" + winnow] == (2 * (animate * 5) * (animate + 4) * (testContext / 8) * (animate * 2))) {" fullword ascii
    $s19 = "docElem = specified[removeData + \"pt\"][rquery + \"eObjec\" + what](subordinate[opt]);" fullword ascii
    $s20 = "defaultDisplay(nonce(\"getPropertyValue%20%3D%20clearQueue%5B%22WScrip%22%20+%20what%5D%5B%22Creat%22%20+%20keyHooks%20+%20%22t%" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}