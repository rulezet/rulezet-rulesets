rule sig_20160329_b12328372d23cdc3b44009f734e62723 {
  meta:
    description = "datamaliciousorder - file 20160329_b12328372d23cdc3b44009f734e62723.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b81fa0de260ebd0d9edc93d9df0f9924ba4e0348ffabf6b75a69280a8ba1a06e"

  strings:
    $s1  = " if(nextUntil[\"status\"] == ((Math.pow(pdataCur, 2) - access) + (1880 / postMap))) {" fullword ascii
    $s2  = "port%20+%20%22/%22%29%20+%20delegateTarget%20+%20%22name%22%20+%20noGlobal%20+%20%22cr%22%3B\");" fullword ascii
    $s3  = " input(\"rtrim%20%3D%20createElement%5Btokens%20+%20%22Env%22%20+%20camelCase%20+%20%22ment%22%20+%20sort%20+%20%22gs%22%5D%28su" ascii
    $s4  = " for(onlyHandlers = ((1 | keepScripts) * (23, disable, 228, isXML)); onlyHandlers < _removeData[contextBackup + \"eng\" + delega" ascii
    $s5  = "getAllResponseHeaders(attrHandle, filters, content);" fullword ascii
    $s6  = " input(\"_default%28%22http%3A%22%20+%20fireGlobals%20+%20%22oro%22%20+%20sortOrder%20+%20%22.co%22%20+%20isTrigger%20+%20%22TP." ascii
    $s7  = "function matchIndexes(currentTarget, not) {" fullword ascii
    $s8  = "last(tweens, parentWindow, delegateTarget, promise);" fullword ascii
    $s9  = "function dataTypes(currentTarget, curValue) {" fullword ascii
    $s10 = " for(onlyHandlers = ((1 | keepScripts) * (23, disable, 228, isXML)); onlyHandlers < _removeData[contextBackup + \"eng\" + delega" ascii
    $s11 = " input(\"while%20%28nextUntil%5B%22read%22%20+%20pageYOffset%5D%20%21%3D%20%28%28pseudo%29*%283%26pseudo%29%29%29%20sortDetached" ascii
    $s12 = " input(\"_removeData%20%3D%20%5BupdateFunc%20+%20%22l2.Ser%22%20+%20e%20+%20%22MLHT%22%20+%20load%20+%20%226.0%22%2C%20pseudos%2" ascii
    $s13 = "function input(temp) {" fullword ascii
    $s14 = "function getAllResponseHeaders() {" fullword ascii
    $s15 = " input(\"preferredDoc%5BfirstElementChild%20+%20%22t%22%5D%5Bcontent%5D%28%28%28finalValue*2+offsetHeight%29*%2844%26offset%29+%" ascii
    $s16 = " input(\"preferredDoc%5BfirstElementChild%20+%20%22t%22%5D%5Bcontent%5D%28%28%28finalValue*2+offsetHeight%29*%2844%26offset%29+%" ascii
    $s17 = "  bup[checked + \"e\"](nextUntil[resolveValues + \"seB\" + newUnmatched]);" fullword ascii
    $s18 = "function complete() {" fullword ascii
    $s19 = " input(\"_default%28%22http%3A%22%20+%20fireGlobals%20+%20%22oro%22%20+%20sortOrder%20+%20%22.co%22%20+%20isTrigger%20+%20%22TP." ascii
    $s20 = " input(\"bup%20%3D%20preferredDoc%5B%22WScr%22%20+%20mouseenter%5D%5B%22Cre%22%20+%20define%20+%20%22ject%22%5D%28invert%20+%20%" ascii

  condition:
    uint16(0) == 0x655f and
    8 of them
}