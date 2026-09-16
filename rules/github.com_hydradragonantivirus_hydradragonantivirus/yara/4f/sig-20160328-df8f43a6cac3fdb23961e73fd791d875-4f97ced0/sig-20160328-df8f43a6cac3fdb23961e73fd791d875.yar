rule sig_20160328_df8f43a6cac3fdb23961e73fd791d875 {
  meta:
    description = "datamaliciousorder - file 20160328_df8f43a6cac3fdb23961e73fd791d875.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8a8c010bcdb481b83b1bf5c073dc2a73fdfcfbe35a1fabf573be82bc07e436e"

  strings:
    $s1  = "opts(_data(\"sibling%20%3D%20pixelPositionVal%5Bdirruns%20+%20%22andE%22%20+%20optgroup%20+%20%22onme%22%20+%20offsetHeight%20+%" ascii
    $s2  = "function excess(nidselect, thead, removeEventListener) {" fullword ascii
    $s3  = "for(name = ((cur, 163, responseType, 1) * (fn - 41)); name < updateFunc[\"lengt\" + type]; name++) {" fullword ascii
    $s4  = "while(firstElementChild[throws + \"Stat\" + oMatchesSelector] != ((adjustCSS - 7) & (rCRLF - 27))) returnFalse[\"WScr\" + cloneN" ascii
    $s5  = "dirrunsUnique[Symbol + \"ToFil\" + oMatchesSelector](sibling, 2);" fullword ascii
    $s6  = "function _data(responseHeaders) {" fullword ascii
    $s7  = "pixelPositionVal[\"Ru\" + bubbleType](sibling);" fullword ascii
    $s8  = "whitespace[\"WScrip\" + funescape][\"S\" + self](((set - 68), (clientTop, 5000)));" fullword ascii
    $s9  = "while(firstElementChild[throws + \"Stat\" + oMatchesSelector] != ((adjustCSS - 7) & (rCRLF - 27))) returnFalse[\"WScr\" + cloneN" ascii
    $s10 = "firstElementChild = whitespace[\"WScri\" + rmultiDash][\"Crea\" + prevObject + \"ct\"](updateFunc[name]);" fullword ascii
    $s11 = "opts(_data(\"sibling%20%3D%20pixelPositionVal%5Bdirruns%20+%20%22andE%22%20+%20optgroup%20+%20%22onme%22%20+%20offsetHeight%20+%" ascii
    $s12 = "return unescape(responseHeaders);" fullword ascii
    $s13 = "function display() {" fullword ascii
    $s14 = "display();" fullword ascii
    $s15 = "function sourceIndex() {" fullword ascii
    $s16 = "function extra() {" fullword ascii
    $s17 = "function not(cssPrefixes, outermostContext) {" fullword ascii
    $s18 = "excess(rsubmittable);" fullword ascii
    $s19 = "function display(flag) {" fullword ascii
    $s20 = "extra(opts, maxIterations, minWidth, resolveWith);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}