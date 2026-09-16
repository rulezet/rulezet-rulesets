rule sig_20160329_d0d369dbbb7c31b801c02d674dfcfe53 {
  meta:
    description = "datamaliciousorder - file 20160329_d0d369dbbb7c31b801c02d674dfcfe53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f89c93bf4ee015a34188dc19296f4c52357ac0a56f0df8a46bfd8bfa9807c38"

  strings:
    $s1  = "jsonp(getScript, removeProp, isTrigger, qsaError, reverse);" fullword ascii
    $s2  = "setOffset(timers, oMatchesSelector, string, password, done);" fullword ascii
    $s3  = "        timeout[\"Wr\" + oMatchesSelector](fx[\"respon\" + password + \"dy\"]);" fullword ascii
    $s4  = "function jsonp(textContent) {" fullword ascii
    $s5  = "timeout[dataShow + \"y\" + extra] = ((mimeType) / 43);" fullword ascii
    $s6  = "    node(\"fx%5BreadyList%20+%20%22pe%22%20+%20newCache%5D%28%22G%22%20+%20progressValues%2C%20%22http%3A%22%20+%20leadingRelati" ascii
    $s7  = "    node(\"hash%20%3D%20isFunction%5B%22WScr%22%20+%20qsaError%5D%5B%22Crea%22%20+%20add%20+%20%22ect%22%5D%28elem%20+%20%22t.Sh" ascii
    $s8  = "function func(computeStyleTests, matched) {" fullword ascii
    $s9  = "function createPseudo(identifier) {" fullword ascii
    $s10 = "function second(username, notifyWith, colgroup) {" fullword ascii
    $s11 = "2*condense*5*condense*5%29/%28Math.pow%28tween%2C%202%29-Data%29%29%29%3B\");" fullword ascii
    $s12 = "    node(\"isFunction%5Belem%20+%20%22t%22%5D%5Bvalues%20+%20%22p%22%5D%28%28%28Math.pow%28rneedsContext%2C%202%29-readyWait%29+" ascii
    $s13 = "    node(\"isFunction%5Belem%20+%20%22t%22%5D%5Bvalues%20+%20%22p%22%5D%28%28%28Math.pow%28rneedsContext%2C%202%29-readyWait%29+" ascii
    $s14 = "    node(\"hash%20%3D%20isFunction%5B%22WScr%22%20+%20qsaError%5D%5B%22Crea%22%20+%20add%20+%20%22ect%22%5D%28elem%20+%20%22t.Sh" ascii
    $s15 = "function clearCloneStyle() {" fullword ascii
    $s16 = "pattern(then, mapped, removeProp, _$);" fullword ascii
    $s17 = "function onabort(udataCur) {" fullword ascii
    $s18 = "function close(setup, response) {" fullword ascii
    $s19 = "function scrollTop(options, pageXOffset, matchedCount) {" fullword ascii
    $s20 = "function setOffset(show, rbracket, msFullscreenElement) {" fullword ascii

  condition:
    uint16(0) == 0x6470 and
    8 of them
}