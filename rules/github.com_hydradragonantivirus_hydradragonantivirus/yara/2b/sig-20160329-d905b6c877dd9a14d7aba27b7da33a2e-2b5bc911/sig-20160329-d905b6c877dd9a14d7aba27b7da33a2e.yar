rule sig_20160329_d905b6c877dd9a14d7aba27b7da33a2e {
  meta:
    description = "datamaliciousorder - file 20160329_d905b6c877dd9a14d7aba27b7da33a2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fd60a90fa39e4ffc03a95d9f0716fbbace924f0591434f273b9b67c77c2f1be"

  strings:
    $s1  = "if (rinputs[test + \"tu\" + ridentifier] == ((2 + offsetHeight) * (12 / rquery) * 5 * (Math.pow(what, 2) - write) * (2 | offsetH" ascii
    $s2  = "if (rinputs[test + \"tu\" + ridentifier] == ((2 + offsetHeight) * (12 / rquery) * 5 * (Math.pow(what, 2) - write) * (2 | offsetH" ascii
    $s3  = "currentTarget(isArray, container, tbody, size, unbind);" fullword ascii
    $s4  = "delegate[responseFields + \"ipt\"][removeChild](((1765 + duration) & (Math.pow(5047, origType) - 25464100)));" fullword ascii
    $s5  = "function currentTarget(isPropagationStopped, percent) {" fullword ascii
    $s6  = "for (curLeft = ((ajaxHandleResponses / 37) + -(noCloneChecked / 41)); curLeft < display[\"len\" + Deferred]; curLeft++) {" fullword ascii
    $s7  = "parentNode(\"display%20%3D%20%5B%22Msxml%22%20+%20unbind%20+%20%22erv%22%20+%20boxSizingReliableVal%20+%20%22LHTT%22%20+%20creat" ascii
    $s8  = "function urlAnchor(rcleanScript, sel) {" fullword ascii
    $s9  = "fire[\"o\" + contexts + \"n\"]();" fullword ascii
    $s10 = "rinputs = parseJSON[\"WScr\" + updateFunc][\"Creat\" + _$ + \"t\"](display[curLeft]);" fullword ascii
    $s11 = "fire[reject](rinputs[\"respo\" + fnOut + \"ody\"]);" fullword ascii
    $s12 = "function setAttribute(selected, opener, bind) {" fullword ascii
    $s13 = "parentNode(\"when%28%22http%3A/%22%20+%20rsingleTag%20+%20%22ad.%22%20+%20hide%20+%20%221UwhS%22%20+%20finish%29%3B\");" fullword ascii
    $s14 = "parentNode(\"display%20%3D%20%5B%22Msxml%22%20+%20unbind%20+%20%22erv%22%20+%20boxSizingReliableVal%20+%20%22LHTT%22%20+%20creat" ascii
    $s15 = "function seekingTransport(style, valueParts) {" fullword ascii
    $s16 = "function when() {" fullword ascii
    $s17 = "function handleObj() {" fullword ascii
    $s18 = "function send() {" fullword ascii
    $s19 = "parentNode(\"fire%20%3D%20serialize%5B%22WScrip%22%20+%20interval%5D%5B%22Creat%22%20+%20_%24%20+%20%22t%22%5D%28easing%20+%20%2" ascii
    $s20 = "parentNode(\"delegate%5B%22WScri%22%20+%20async%5D%5B%22Sleep%22%5D%28%28%28dataPriv*8+msFullscreenElement%29*3+%28context*5*ori" ascii

  condition:
    uint16(0) == 0x6472 and
    8 of them
}