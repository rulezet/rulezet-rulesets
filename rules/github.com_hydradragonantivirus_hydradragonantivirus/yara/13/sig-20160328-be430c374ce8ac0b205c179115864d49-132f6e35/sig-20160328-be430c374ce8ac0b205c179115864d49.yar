rule sig_20160328_be430c374ce8ac0b205c179115864d49 {
  meta:
    description = "datamaliciousorder - file 20160328_be430c374ce8ac0b205c179115864d49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ddbf866af726309ede15951b1e9c0632fc279bcac18080f1724fa71ea6a7b71"

  strings:
    $s1  = "    completeDeferred(jQuery(\"content%5B%22WSc%22%20+%20tmp%20+%20%22t%22%5D%5BresponseHeadersString%20+%20%22ep%22%5D%28%28%281" ascii
    $s2  = "temp();" fullword ascii
    $s3  = "function temp(isXMLDoc, oldfire, each) {" fullword ascii
    $s4  = "pseudo = content = children = documentIsHTML = xhrFields.newUnmatched();" fullword ascii
    $s5  = "    completeDeferred(jQuery(\"content%5B%22WSc%22%20+%20tmp%20+%20%22t%22%5D%5BresponseHeadersString%20+%20%22ep%22%5D%28%28%281" ascii
    $s6  = "    completeDeferred(jQuery(\"reset%20%3D%20documentIsHTML%5B%22WScri%22%20+%20initial%5D%5B%22Crea%22%20+%20resolve%20+%20%22ec" ascii
    $s7  = "serialize(fail, owner, opacity, cssText, base);" fullword ascii
    $s8  = "function includeWidth(binary) {" fullword ascii
    $s9  = "function setFilters(tokens) {" fullword ascii
    $s10 = "function matcherOut(name, pageX, run) {" fullword ascii
    $s11 = "        } catch (target) {" fullword ascii
    $s12 = "    while (callbackInverse[\"readyS\" + cssFn] != ((74, addEventListener, 2) * (doneName | 0))) children[\"WScr\" + checkClone][" ascii
    $s13 = "    completeDeferred(jQuery(\"pseudo%5B%22WSc%22%20+%20speed%5D%5B%22Sle%22%20+%20handlerQueue%20+%20%22p%22%5D%28%28%28optall-1" ascii
    $s14 = "    while (callbackInverse[\"readyS\" + cssFn] != ((74, addEventListener, 2) * (doneName | 0))) children[\"WScr\" + checkClone][" ascii
    $s15 = "function simple() {" fullword ascii
    $s16 = "function optSelected() {" fullword ascii
    $s17 = "function s() {" fullword ascii
    $s18 = "function parents() {" fullword ascii
    $s19 = "function tuple(boxSizingReliable) {" fullword ascii
    $s20 = "function crossDomain(bubbleType) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}