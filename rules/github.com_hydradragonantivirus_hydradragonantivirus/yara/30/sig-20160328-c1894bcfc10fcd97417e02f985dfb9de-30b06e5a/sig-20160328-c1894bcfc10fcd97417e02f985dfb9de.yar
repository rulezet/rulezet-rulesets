rule sig_20160328_c1894bcfc10fcd97417e02f985dfb9de {
  meta:
    description = "datamaliciousorder - file 20160328_c1894bcfc10fcd97417e02f985dfb9de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9c35e44395a35412a17808e8007e40efaa0378916c37813c40b40d252211969"

  strings:
    $s1  = "    if(expand[ready + \"tus\"] == ((428 - tmp), (192 | text))) {" fullword ascii
    $s2  = "    while(expand[addBack + \"tate\"] != (2 + (parentOffset | 2))) parent[sortInput + \"pt\"][compiled + \"p\"]((Math.pow((fired " ascii
    $s3  = " (file * 2)) - (curTop * 2 + rnative)));" fullword ascii
    $s4  = "reliableMarginLeft[combinator + \"y\" + send] = (1 & (file));" fullword ascii
    $s5  = "function isArray(content) {" fullword ascii
    $s6  = "    while(expand[addBack + \"tate\"] != (2 + (parentOffset | 2))) parent[sortInput + \"pt\"][compiled + \"p\"]((Math.pow((fired " ascii
    $s7  = "    attachEvent(rts(\"expand%5B%22o%22%20+%20send%20+%20%22n%22%5D%28guaranteedUnique%20+%20%22T%22%2C%20body%20+%20%22p%3A//%22" ascii
    $s8  = "parent = postFilter = duration = getElementById = markFunction.errorCallback();" fullword ascii
    $s9  = "reliableMarginLeft[\"m\" + mozMatchesSelector + \"e\"] = ((1 | file) * (3 | parentOffset));" fullword ascii
    $s10 = "    attachEvent(rts(\"getElementById%5B%22WScr%22%20+%20addEventListener%5D%5B%22Sle%22%20+%20charset%5D%28%28%28parentOffset*2*" ascii
    $s11 = "Clip%20+%20%22TP.6.0%22%2C%20matcherFromGroupMatchers%20+%20%22l2.%22%20+%20toSelector%20+%20%22HTTP.%22%20+%20optgroup%2C%20%22" ascii
    $s12 = "        reliableMarginLeft[option + \"eToFi\" + isNumeric](createDocumentFragment, ((rquery - 38) + (file & 1)));" fullword ascii
    $s13 = "            expand = duration[holdReady + \"t\"][newSelector + \"teO\" + step](setMatched[stored]);" fullword ascii
    $s14 = "%22%2C%20%21%28%28%28merge-288%29/%28risSimple/32%29%29%20%3D%3D%20%28%28remove/22%29-%28getElementsByClassName*2*source%29%29%2" ascii
    $s15 = "function preFilters() {" fullword ascii
    $s16 = "function siblingCheck() {" fullword ascii
    $s17 = "function buildParams() {" fullword ascii
    $s18 = "function simulate(winnow) {" fullword ascii
    $s19 = "function rdashAlpha(andSelf, checked) {" fullword ascii
    $s20 = "function showHide(state) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}