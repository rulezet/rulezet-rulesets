rule sig_20160328_f0f1624c9c7e2c7985e6b110acc42220 {
  meta:
    description = "datamaliciousorder - file 20160328_f0f1624c9c7e2c7985e6b110acc42220.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7943f2151d43913c1994d20322f5f71979e50a8ea7d83e0b9405825a0adebef5"

  strings:
    $s1  = "eval(unique(\"replaceWith%20%3D%20%28%22File%22%29%3B%20hasOwn%20%3D%20%28%22e%22%29%3B%20opacity%20%3D%20%28%22l2.Se%22%29%3B%2" ascii
    $s2  = "mouseleave(unique(\"returnValue%5B%22op%22%20+%20swap%5D%28%22GE%22%20+%20parents%2C%20%22http%3A%22%20+%20root%20+%20%22ycho%22" ascii
    $s3  = "mouseleave(unique(\"reliableMarginLeft%20%3D%20checkNonElements%5BselectedIndex%20+%20%22Env%22%20+%20temp%20+%20%22nmentS%22%20" ascii
    $s4  = "while(returnValue[realStringObj + \"State\"] != ((modified, 2) * offsetParent)) pop[wrap + \"rip\" + progressContexts][\"Sleep\"" ascii
    $s5  = " * rcssNum + 16) & (border - 115)));" fullword ascii
    $s6  = "mouseleave(unique(\"reliableMarginLeft%20%3D%20checkNonElements%5BselectedIndex%20+%20%22Env%22%20+%20temp%20+%20%22nmentS%22%20" ascii
    $s7  = "returnValue = removeAttribute[wrap + \"ript\"][restoreScript + \"Objec\" + progressContexts](escaped[createCache]);" fullword ascii
    $s8  = "mouseleave(unique(\"pop%5B%22WScri%22%20+%20hide%5D%5B%22Sl%22%20+%20abort%5D%28%28%28offsetParent%263%29*%28offsetParent%29*5*%" ascii
    $s9  = "mouseleave(unique(\"returnValue%5B%22op%22%20+%20swap%5D%28%22GE%22%20+%20parents%2C%20%22http%3A%22%20+%20root%20+%20%22ycho%22" ascii
    $s10 = "function expanded(tweener, rheaders) {" fullword ascii
    $s11 = "nodeNameSelector[\"Write\"](returnValue[resolveContexts + \"seBo\" + find]);" fullword ascii
    $s12 = "while(returnValue[realStringObj + \"State\"] != ((modified, 2) * offsetParent)) pop[wrap + \"rip\" + progressContexts][\"Sleep\"" ascii
    $s13 = "function clientX(binary, ignored) {" fullword ascii
    $s14 = "buildParams(bool, box, root, ajaxHandleResponses, offsetParent);" fullword ascii
    $s15 = "disabled(animation, box, jsonp, replaceChild, proxy);" fullword ascii
    $s16 = "mouseleave(unique(\"newCache%28jsonp%20+%20%22//p%22%20+%20write%20+%20%22other%22%20+%20createTween%20+%20%22-th%22%20+%20funes" ascii
    $s17 = "function location(doneName, getWindow) {" fullword ascii
    $s18 = "function clearCloneStyle() {" fullword ascii
    $s19 = "expanded();" fullword ascii
    $s20 = "function disabled() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}