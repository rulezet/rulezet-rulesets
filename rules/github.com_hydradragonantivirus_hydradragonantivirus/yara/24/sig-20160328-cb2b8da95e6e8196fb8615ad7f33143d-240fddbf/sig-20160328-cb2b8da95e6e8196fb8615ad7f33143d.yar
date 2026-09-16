rule sig_20160328_cb2b8da95e6e8196fb8615ad7f33143d {
  meta:
    description = "datamaliciousorder - file 20160328_cb2b8da95e6e8196fb8615ad7f33143d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f32c1ab87ffed4e93b1f49c4718151790dc6d0b3bb841d53b89af46300a8628"

  strings:
    $s1  = "v * 2))) nextAll[\"WScrip\" + bySet][\"Slee\" + contains](((nonce + 8) - (key)));" fullword ascii
    $s2  = "function delegateTarget(_data) {" fullword ascii
    $s3  = "toggleClass(delegateTarget(\"nextAll%5BeventDoc%20+%20%22ript%22%5D%5Bsupport%20+%20%22p%22%5D%28%28%285*set*2*marginDiv*5*margi" ascii
    $s4  = "elementMatchers[Symbol + \"n\"](getBoundingClientRect);" fullword ascii
    $s5  = "for(defineProperty = ((1 + remove) + -1); defineProperty < matches[rhtml + \"engt\" + deep]; defineProperty++) {" fullword ascii
    $s6  = "responseFields[\"ty\" + contains + \"e\"] = ((22 - until) | (2 - marginDiv));" fullword ascii
    $s7  = "while(class2type[raw + \"yStat\" + msFullscreenElement] != ((addToPrefiltersOrTransports & 61), (checkNonElements - 45), (margin" ascii
    $s8  = "while(class2type[raw + \"yStat\" + msFullscreenElement] != ((addToPrefiltersOrTransports & 61), (checkNonElements - 45), (margin" ascii
    $s9  = "function rcleanScript(noBubble, wait) {" fullword ascii
    $s10 = "function addGetHookIf() {" fullword ascii
    $s11 = "addGetHookIf(selector, name);" fullword ascii
    $s12 = "responseFields[index + \"od\" + msFullscreenElement] = ((42 / elem) | (35 / appendTo));" fullword ascii
    $s13 = "sortStable(getComputedStyle, toggleClass, index, getElementsByName, crossDomain);" fullword ascii
    $s14 = "timerId(key, ifModified, match);" fullword ascii
    $s15 = "function curPosition(inspect, complete, url) {" fullword ascii
    $s16 = "function rfocusable() {" fullword ascii
    $s17 = "function timerId() {" fullword ascii
    $s18 = "function firstElementChild() {" fullword ascii
    $s19 = "function relative(show) {" fullword ascii
    $s20 = "function init(setPositiveNumber) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}