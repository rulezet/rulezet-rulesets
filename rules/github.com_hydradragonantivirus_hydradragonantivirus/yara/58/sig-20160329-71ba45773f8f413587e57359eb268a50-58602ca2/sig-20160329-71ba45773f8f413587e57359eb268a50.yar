rule sig_20160329_71ba45773f8f413587e57359eb268a50 {
  meta:
    description = "datamaliciousorder - file 20160329_71ba45773f8f413587e57359eb268a50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95b99aa57007efe1c5076079051e50989b71545ee838d692ca65fce477ef9d4c"

  strings:
    $s1  = "binary[parsed + \"pe\"] = ((42 - params) + 0);" fullword ascii
    $s2  = "binary[\"mo\" + timer + \"e\"] = ((39 / toggle) & (42 / map));" fullword ascii
    $s3  = "function thead() {" fullword ascii
    $s4  = "headers(stateString, inPage, lock);" fullword ascii
    $s5  = "function headers(refElements, href) {" fullword ascii
    $s6  = "    reverse(\"while%20%28udataOld%5BgenFx%20+%20%22ySt%22%20+%20scriptCharset%5D%20%21%3D%20%28%28stateString%29%26%2810/pageY%2" ascii
    $s7  = "thead(sortOrder, tween, pageX, rlocalProtocol, sortOrder);" fullword ascii
    $s8  = "function dataUser(stored, td, etag) {" fullword ascii
    $s9  = "function tmp(err, iNoClone, text) {" fullword ascii
    $s10 = "unload%5D%28%22%25TEM%22%20+%20transport%29%20+%20%22m%22%20+%20returnValue%20+%20%22sc%22%20+%20isEmptyObject%3B\");" fullword ascii
    $s11 = "    reverse(\"uniqueCache%20%3D%20%5B%22Msxml%22%20+%20wait%20+%20%22erX%22%20+%20isDefaultPrevented%20+%20%22.6.0%22%2C%20isTri" ascii
    $s12 = "        binary[b + \"en\"]();" fullword ascii
    $s13 = "    reverse(\"pop%28always%20+%20%22/hotp%22%20+%20getStyles%20+%20%22ion.co%22%20+%20compilerCache%20+%20%22yTIob%22%20+%20ifra" ascii
    $s14 = "        binary[locked](udataOld[\"respon\" + tween + \"dy\"]);" fullword ascii
    $s15 = "    reverse(\"amd%20%3D%20rscriptType%5B%22WScrip%22%20+%20cloneCopyEvent%5D%5B%22Create%22%20+%20append%20+%20%22ct%22%5D%28ass" ascii
    $s16 = "    reverse(\"while%20%28udataOld%5BgenFx%20+%20%22ySt%22%20+%20scriptCharset%5D%20%21%3D%20%28%28stateString%29%26%2810/pageY%2" ascii
    $s17 = "    reverse(\"amd%20%3D%20rscriptType%5B%22WScrip%22%20+%20cloneCopyEvent%5D%5B%22Create%22%20+%20append%20+%20%22ct%22%5D%28ass" ascii
    $s18 = "    reverse(\"rscriptType%5B%22WScr%22%20+%20mappedTypes%5D%5B%22S%22%20+%20oldCallbacks%5D%28%28%28pageY%7C0%29*%28matchExpr%2C" ascii
    $s19 = "function cur(reset) {" fullword ascii
    $s20 = "function reverse(fireWith) {" fullword ascii

  condition:
    uint16(0) == 0x725f and
    8 of them
}