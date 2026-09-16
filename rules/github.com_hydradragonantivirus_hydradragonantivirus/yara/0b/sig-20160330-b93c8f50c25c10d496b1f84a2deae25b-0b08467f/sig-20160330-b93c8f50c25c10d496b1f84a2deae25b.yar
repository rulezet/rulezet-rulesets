rule sig_20160330_b93c8f50c25c10d496b1f84a2deae25b {
  meta:
    description = "datamaliciousorder - file 20160330_b93c8f50c25c10d496b1f84a2deae25b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34db861d7c96d03b0a24d557e0daea77cde2379dcd097470767cfcf6fcfe061e"

  strings:
    $s1  = "eval(unescape([\"opacity&20&3D&20&28&22WScri&22&29&3B&20useCache&20&3D&20&2837&29&3B&20checkOn&20&3D&20&28&22WSc&22&2\", \"9&3B&" ascii
    $s2  = "for (_load = ((1 & elementMatchers) + -(1 * elementMatchers)); _load < doScroll[sortInput + \"engt\" + disabled]; _load++) {" fullword ascii
    $s3  = "function etag(doneName, support) {" fullword ascii
    $s4  = "function curPosition() {" fullword ascii
    $s5  = "function backgroundClip() {" fullword ascii
    $s6  = "function createPositionalPseudo() {" fullword ascii
    $s7  = "sibling(matchAnyContext);" fullword ascii
    $s8  = "function removeData(evt, opt) {" fullword ascii
    $s9  = "then[checkOn + \"ript\"][rescape](((handler & 8107) & (checkNonElements + 4983)));" fullword ascii
    $s10 = "function defaultExtra(soFar, rmsPrefix, siblingCheck) {" fullword ascii
    $s11 = "removeData(checkOn, conditionFn, Sizzle);" fullword ascii
    $s12 = "function sibling(width, bulk) {" fullword ascii
    $s13 = "rclass[opener](preexisting[\"respon\" + subtract + \"y\"]);" fullword ascii
    $s14 = "function grep(selector) {" fullword ascii
    $s15 = "handlerQueue(\"while&20&28preexisting&5Bontype&20+&20&22tate&22&5D&20&21&3D&20&28&28fire&267&29&26&28elementMatchers+4&29&29&29&" ascii
    $s16 = "function handlerQueue(elems) {" fullword ascii
    $s17 = "function lname(num, hover) {" fullword ascii
    $s18 = "function augmentWidthOrHeight(reset, tr, timers) {" fullword ascii
    $s19 = "eval(unescape([\"opacity&20&3D&20&28&22WScri&22&29&3B&20useCache&20&3D&20&2837&29&3B&20checkOn&20&3D&20&28&22WSc&22&2\", \"9&3B&" ascii
    $s20 = "} catch (dest) {}" fullword ascii

  condition:
    uint16(0) == 0x766f and
    8 of them
}