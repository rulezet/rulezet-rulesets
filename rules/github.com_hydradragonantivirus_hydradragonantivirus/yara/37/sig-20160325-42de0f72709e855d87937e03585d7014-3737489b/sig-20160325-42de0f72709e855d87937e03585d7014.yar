rule sig_20160325_42de0f72709e855d87937e03585d7014 {
  meta:
    description = "datamaliciousorder - file 20160325_42de0f72709e855d87937e03585d7014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36c01f3ecf7267696a72f4c90ad3f053b6cc7c49d97e92af392824d14c68a527"

  strings:
    $s1  = "attr = rnoContent[setRequestHeader + \"Enviro\" + compareDocumentPosition + \"ntStri\" + originAnchor](\"%TEMP%\" + reverse) + " ascii
    $s2  = "attr = rnoContent[setRequestHeader + \"Enviro\" + compareDocumentPosition + \"ntStri\" + originAnchor](\"%TEMP%\" + reverse) + " ascii
    $s3  = "pageX[getJSON + \"ipt\"][wait + \"ee\" + not](((22 | forward), 103, (xhrFields, 144, accepts, 76), (hidden, 141, wrapAll, 10000)" ascii
    $s4  = "sortOrder = \"P.6.\", rfxtypes = 2, disableScript = (function random() {}, \"r\");" fullword ascii
    $s5  = "function dataType(focus, replaceWith, rparentsprev, rcleanScript) {" fullword ascii
    $s6  = "forward = 4, hold = \"Activ\", letter = \"ition\", postFinder = \"c\", toggleClass = \"l2.XM\";" fullword ascii
    $s7  = "return replaceWith[rcleanScript](focus, rparentsprev);" fullword ascii
    $s8  = "doScroll(rmsPrefix, isBorderBox, hold, postFinder, animate);" fullword ascii
    $s9  = "modified(forward);" fullword ascii
    $s10 = "eval(lock(\"parse%20%3D%20rnoContent%3B\"));" fullword ascii
    $s11 = "cloneCopyEvent[\"clos\" + hide]();" fullword ascii
    $s12 = "function iframe() {" fullword ascii
    $s13 = "flag = rootjQuery = pageX = delegate = random.charset();" fullword ascii
    $s14 = "eval(lock(\"queue%28%22Respon%22%20+%20settings%20+%20%22ody%22%2C%20%28%28holdReady/11%29-%28checkbox%261%29%29%2C%20opts%2C%20" ascii
    $s15 = "eval(lock(\"queue%28%22Respon%22%20+%20settings%20+%20%22ody%22%2C%20%28%28holdReady/11%29-%28checkbox%261%29%29%2C%20opts%2C%20" ascii
    $s16 = "function queue(dataAndEvents, code, replaceWith, username) {" fullword ascii
    $s17 = "iframe(accepts, hide, rmsPrefix, rfxtypes, rmargin);" fullword ascii
    $s18 = "function modified() {" fullword ascii
    $s19 = "function ontype() {" fullword ascii
    $s20 = "function prototype() {" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}