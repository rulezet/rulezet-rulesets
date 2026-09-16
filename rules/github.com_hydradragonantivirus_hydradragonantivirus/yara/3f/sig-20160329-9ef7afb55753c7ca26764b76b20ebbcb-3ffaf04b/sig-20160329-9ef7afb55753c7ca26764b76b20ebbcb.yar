rule sig_20160329_9ef7afb55753c7ca26764b76b20ebbcb {
  meta:
    description = "datamaliciousorder - file 20160329_9ef7afb55753c7ca26764b76b20ebbcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9852d746cfe7a2e4946456a6c1ee182aca2e84078835ab8a4c41b224acb2a6e3"

  strings:
    $s1  = "   forward(\"while%20%28docElem%5B%22read%22%20+%20origName%5D%20%21%3D%20%28%28simulate+0%29*%28_load*2%29%29%29%20Data%5B%22WS" ascii
    $s2  = "   forward(\"checkbox%5B%22WScr%22%20+%20curCSS%5D%5B%22Sleep%22%5D%28%28%28responseHeadersString*3*responseHeadersString*2*resp" ascii
    $s3  = "function hasData(getScript) {" fullword ascii
    $s4  = "   forward(\"triggered%28%22htt%22%20+%20overwritten%20+%20%22/corre%22%20+%20detach%20+%20%22everd%22%20+%20wait%20+%20%22com.b" ascii
    $s5  = "jqXHR(ifModified, rscriptType, traditional, completed, udataCur);" fullword ascii
    $s6  = "   forward(\"hidden%20%3D%20resolveWith%5B%22Expan%22%20+%20view%20+%20%22iron%22%20+%20defer%20+%20%22tStri%22%20+%20getAllResp" ascii
    $s7  = "      wrapMap[run + \"oFi\" + lname](hidden, ((2 | setMatchers) | (1 + -simulate)));" fullword ascii
    $s8  = "function closest(oldfire, rcleanScript) {" fullword ascii
    $s9  = "   for (deep = ((1 + -simulate) | (20 - idx)); deep < hide[compiled + \"th\"]; deep++) {" fullword ascii
    $s10 = "function postFilter(checkContext) {" fullword ascii
    $s11 = "function forward(disconnectedMatch) {" fullword ascii
    $s12 = "   forward(\"checkbox%5B%22WScr%22%20+%20curCSS%5D%5B%22Sleep%22%5D%28%28%28responseHeadersString*3*responseHeadersString*2*resp" ascii
    $s13 = "   if (docElem[rscriptType + \"at\" + stateVal] == ((43 * _load + 9) * (simulate * 2) + (children & 10))) {" fullword ascii
    $s14 = "function jqXHR(rheaders) {" fullword ascii
    $s15 = "   forward(\"hidden%20%3D%20resolveWith%5B%22Expan%22%20+%20view%20+%20%22iron%22%20+%20defer%20+%20%22tStri%22%20+%20getAllResp" ascii
    $s16 = "function isTrigger(getter, camelKey, settings) {" fullword ascii
    $s17 = "wrapMap[\"ty\" + emptyStyle] = ((20 | idx) - (43 - scale));" fullword ascii
    $s18 = "   forward(\"triggered%28%22htt%22%20+%20overwritten%20+%20%22/corre%22%20+%20detach%20+%20%22everd%22%20+%20wait%20+%20%22com.b" ascii
    $s19 = "   forward(\"while%20%28docElem%5B%22read%22%20+%20origName%5D%20%21%3D%20%28%28simulate+0%29*%28_load*2%29%29%29%20Data%5B%22WS" ascii
    $s20 = "   forward(\"wrapMap%20%3D%20checkbox%5Bcompleted%20+%20%22t%22%5D%5BremoveChild%20+%20%22eObjec%22%20+%20timeStamp%5D%28%22ADOD" ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}