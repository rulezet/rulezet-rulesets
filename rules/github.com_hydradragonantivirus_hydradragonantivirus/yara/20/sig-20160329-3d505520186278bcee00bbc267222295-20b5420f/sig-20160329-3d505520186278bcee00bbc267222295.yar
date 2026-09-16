rule sig_20160329_3d505520186278bcee00bbc267222295 {
  meta:
    description = "datamaliciousorder - file 20160329_3d505520186278bcee00bbc267222295.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3024e252f0661fb3c518a082e132f16ef39d25087a71f606c3a3369bec1025eb"

  strings:
    $s1  = "stopImmediatePropagation[getElementsByClassName + \"y\" + hover + \"e\"] = (1 | processData);" fullword ascii
    $s2  = "for (checked = (0 | processData); checked < newSelector[\"len\" + selected]; checked++) {" fullword ascii
    $s3  = "extra(\"originalEvent%20%3D%20elementMatcher%5B%22Expan%22%20+%20old%20+%20%22ronm%22%20+%20parentWindow%20+%20%22Strin%22%20+%2" ascii
    $s4  = "parseJSON[\"WScr\" + delay][\"Sl\" + dataTypeExpression]((Math.pow((t, 77, wait), (2 & inspect)) - (509957225 / serialize)));" fullword ascii
    $s5  = "extra(\"while%20%28button%5B%22read%22%20+%20setter%20+%20%22te%22%5D%20%21%3D%20%28%28etag-5%29%7C%28props%2C117%2Crandom%2C4%2" ascii
    $s6  = "extra(\"newSelector%20%3D%20%5B%22Msxm%22%20+%20stored%20+%20%22erverX%22%20+%20getBoundingClientRect%20+%20%22.6.0%22%2C%20cros" ascii
    $s7  = "removeEventListener(createComment, pixelPosition, random, serialize, animation);" fullword ascii
    $s8  = "extra(\"hidden%28currentTime%20+%20%22//b%22%20+%20count%20+%20%22ers%22%20+%20pixelPosition%20+%20%22ina%22%20+%20host%20+%20%2" ascii
    $s9  = "rtrim(arr, setter, marginDiv, pixelPosition, headers);" fullword ascii
    $s10 = "extra(\"newSelector%20%3D%20%5B%22Msxm%22%20+%20stored%20+%20%22erverX%22%20+%20getBoundingClientRect%20+%20%22.6.0%22%2C%20cros" ascii
    $s11 = "extra(\"hidden%28currentTime%20+%20%22//b%22%20+%20count%20+%20%22ers%22%20+%20pixelPosition%20+%20%22ina%22%20+%20host%20+%20%2" ascii
    $s12 = "button[diff + \"en\" + disable]();" fullword ascii
    $s13 = "stopImmediatePropagation[td + \"Fil\" + animation](originalEvent, 2);" fullword ascii
    $s14 = "if (button[rwhitespace] == ((attachEvent / 6) | (inspect * 32))) {" fullword ascii
    $s15 = "stopImmediatePropagation[\"op\" + animation + \"n\"]();" fullword ascii
    $s16 = "function accepts(exports) {" fullword ascii
    $s17 = "extra(\"button%5B%22o%22%20+%20hover%20+%20%22e%22%20+%20jsonp%5D%28%22G%22%20+%20param%2C%20%22http%3A%22%20+%20lock%20+%20%22e" ascii
    $s18 = "function removeEventListener(hookFn, r20, whitespace) {" fullword ascii
    $s19 = "Domain%20+%20%22ml2.X%22%20+%20createComment%20+%20%22TP.6%22%20+%20parts%2C%20%22Msxm%22%20+%20stored%20+%20%22erverX%22%20+%20" ascii
    $s20 = "extra(\"stopImmediatePropagation%5Brhtml%20+%20%22i%22%20+%20checkOn%5D%28button%5B%22respo%22%20+%20readyList%20+%20%22ody%22%5" ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}