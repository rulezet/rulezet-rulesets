rule sig_20160328_8b7918863983e30f4d9bec4a3eb00655 {
  meta:
    description = "datamaliciousorder - file 20160328_8b7918863983e30f4d9bec4a3eb00655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d69670a533c0449bfd442bc0c6e81cb30c7e260f6e961e909ec3c3e3c9dff34d"

  strings:
    $s1  = "eval(host(\"curValue%20%3D%20%28%22ngs%22%29%2C%20actualDisplay%20%3D%20%28%22oFile%22%29%2C%20tfoot%20%3D%20%2815%29%2C%20once%" ascii
    $s2  = "   if(getWindow[\"s\" + matcher + \"s\"] == (Math.pow((compile * 2 + createTween), (2 & postFilter)) - (44924 & submit))) {" fullword ascii
    $s3  = "   while(getWindow[getter + \"dyStat\" + els] != ((props / 35) - (tfoot + 8))) innerHTML[\"WScri\" + onreadystatechange][\"Slee" ascii
    $s4  = "   while(getWindow[getter + \"dyStat\" + els] != ((props / 35) - (tfoot + 8))) innerHTML[\"WScri\" + onreadystatechange][\"Slee" ascii
    $s5  = "function targets() {" fullword ascii
    $s6  = "   setMatcher(host(\"targets%28register%20+%20%22p%3A//%22%20+%20delegateType%20+%20%22mmi%22%20+%20getElementsByName%20+%20%22i" ascii
    $s7  = "   setMatcher(host(\"targets%28register%20+%20%22p%3A//%22%20+%20delegateType%20+%20%22mmi%22%20+%20getElementsByName%20+%20%22i" ascii
    $s8  = "function manipulationTarget(left, pageX, pixelMarginRight) {" fullword ascii
    $s9  = "function postMap(removeEventListener) {" fullword ascii
    $s10 = "function scrollLeft(temp, strAbort) {" fullword ascii
    $s11 = "         getWindow = charset[\"WScri\" + onreadystatechange][\"Create\" + nid + \"ct\"](serialize[stateString]);" fullword ascii
    $s12 = "   setMatcher(host(\"getWindow%5Busing%20+%20%22pe%22%20+%20slow%5D%28%22G%22%20+%20responseContainer%2C%20%22htt%22%20+%20_remo" ascii
    $s13 = "   setMatcher(host(\"getWindow%5Busing%20+%20%22pe%22%20+%20slow%5D%28%22G%22%20+%20responseContainer%2C%20%22htt%22%20+%20_remo" ascii
    $s14 = "function host(needsContext) {" fullword ascii
    $s15 = "eval(host(\"curValue%20%3D%20%28%22ngs%22%29%2C%20actualDisplay%20%3D%20%28%22oFile%22%29%2C%20tfoot%20%3D%20%2815%29%2C%20once%" ascii
    $s16 = "   setMatcher(host(\"serialize%20%3D%20%5B%22Msxml%22%20+%20options%20+%20%22erve%22%20+%20now%20+%20%22HTT%22%20+%20completed%2" ascii
    $s17 = "function isArrayLike(combinator, rbrace) {" fullword ascii
    $s18 = "   setMatcher(host(\"charset%5B%22WSc%22%20+%20preventDefault%5D%5B%22Sle%22%20+%20not%5D%28%28Math.pow%28%28678*emptyStyle+19%2" ascii
    $s19 = "   setMatcher(host(\"charset%5B%22WSc%22%20+%20preventDefault%5D%5B%22Sle%22%20+%20not%5D%28%28Math.pow%28%28678*emptyStyle+19%2" ascii
    $s20 = "tween(fired, rcssNum, truncate, compile);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}