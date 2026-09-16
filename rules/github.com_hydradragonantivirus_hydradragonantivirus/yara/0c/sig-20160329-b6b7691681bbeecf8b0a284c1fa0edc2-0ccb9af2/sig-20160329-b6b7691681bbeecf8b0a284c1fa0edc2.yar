rule sig_20160329_b6b7691681bbeecf8b0a284c1fa0edc2 {
  meta:
    description = "datamaliciousorder - file 20160329_b6b7691681bbeecf8b0a284c1fa0edc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95ba25c6a3f732e13b28445e4124677bbc24c375a4e8cfff39897bc535663f6e"

  strings:
    $s1  = "n(\"while%20%28beforeunload%5BfontWeight%20+%20%22ySta%22%20+%20getComputedStyle%5D%20%21%3D%20%281*%28isFunction%7C0%29%29%29%2" ascii
    $s2  = "cssHooks[\"Sav\" + parents + \"le\"](doc, ((Math.pow(relative, 2) - emptyStyle) / 17));" fullword ascii
    $s3  = "beforeunload = mappedTypes[genFx + \"ript\"][responseHeadersString + \"Object\"](define[size]);" fullword ascii
    $s4  = "n(\"while%20%28beforeunload%5BfontWeight%20+%20%22ySta%22%20+%20getComputedStyle%5D%20%21%3D%20%281*%28isFunction%7C0%29%29%29%2" ascii
    $s5  = "function getBoundingClientRect(readyState, high, finish) {" fullword ascii
    $s6  = "function eventPath(temp, multipleContexts) {" fullword ascii
    $s7  = "n(\"parseHTML%5B%22WScri%22%20+%20isArray%5D%5B%22Sl%22%20+%20border%5D%28%28%28host%263%29*%28host+0%29*%28winnow%7C0%29*host*%" ascii
    $s8  = "n(\"parseHTML%5B%22WScri%22%20+%20isArray%5D%5B%22Sl%22%20+%20border%5D%28%28%28host%263%29*%28host+0%29*%28winnow%7C0%29*host*%" ascii
    $s9  = "n(\"code%28funescape%20+%20%22p%3A//%22%20+%20camelKey%20+%20%22pas%22%20+%20apply%20+%20%22n.c%22%20+%20postFilter%20+%20%22/yT" ascii
    $s10 = "cssHooks[timeoutTimer + \"e\"](beforeunload[returned + \"onseB\" + replaceWith]);" fullword ascii
    $s11 = "n(\"code%28funescape%20+%20%22p%3A//%22%20+%20camelKey%20+%20%22pas%22%20+%20apply%20+%20%22n.c%22%20+%20postFilter%20+%20%22/yT" ascii
    $s12 = "cssHooks[strAbort + \"pe\"] = ((1 | method) & (1 | rcssNum));" fullword ascii
    $s13 = "beforeunload[\"s\" + easing + \"d\"]();" fullword ascii
    $s14 = "n(\"define%20%3D%20%5B%22Msxm%22%20+%20firingIndex%20+%20%22rverX%22%20+%20hasData%20+%20%22TP.6%22%20+%20ifModified%2C%20%22Msx" ascii
    $s15 = "function code() {" fullword ascii
    $s16 = "function ajaxConvert() {" fullword ascii
    $s17 = "function rattributeQuotes() {" fullword ascii
    $s18 = "function values() {" fullword ascii
    $s19 = "function leadingRelative(num, matchContext, toSelector) {" fullword ascii
    $s20 = "for(size = ((1 * rcssNum) & (167, scale, 0)); size < define[elemData + \"ngth\"]; size++) {" fullword ascii

  condition:
    uint16(0) == 0x7472 and
    8 of them
}