rule _20160827_cbe13003e29867c8403f06286084a3a9_20160902_2b036880e3cf_685 {
  meta:
    description = "datamaliciousorder - from files 20160827_cbe13003e29867c8403f06286084a3a9.js, 20160902_2b036880e3cfbb69adfa56377e81eb7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0858946b854878c76424d3a7820caf172d82adbddab1fb0ab9c466cb1ffab1ad"
    hash2       = "330c9f179babdf1499aad677e4780791972e42c5e9489c5aa762a4165e7e0048"

  strings:
    $s1 = "        if (0 < c && c != b) return window.location.replace(\"http://www.paypal.com/\")," fullword ascii
    $s2 = "        if (0 < a && 5 != a) return window.location.replace(\"http://www.paypal.com/\")," fullword ascii
    $s3 = "    if (!document.env.MBfn.value || !a || !d || \"00\" == c || \"00\" == b) return window.location.replace(\"http://www.paypal.c" ascii
    $s4 = "    if (!document.env.MBfn.value || !a || !d || \"00\" == c || \"00\" == b) return window.location.replace(\"http://www.paypal.c" ascii
    $s5 = "    if (!ax) return window.location.replace(\"http://www.paypal.com/\")," fullword ascii
    $s6 = "var _0x3a657d = (function(a) {" fullword ascii
    $s7 = "function _0x529953() {" fullword ascii
    $s8 = "    if (\"United States\" == document.env.MBctn.value) {" fullword ascii
    $s9 = "        return c && c % 10 === 0" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}