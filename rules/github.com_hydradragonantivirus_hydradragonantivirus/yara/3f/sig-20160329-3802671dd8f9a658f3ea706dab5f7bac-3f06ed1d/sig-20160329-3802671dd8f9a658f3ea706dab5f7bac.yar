rule sig_20160329_3802671dd8f9a658f3ea706dab5f7bac {
  meta:
    description = "datamaliciousorder - file 20160329_3802671dd8f9a658f3ea706dab5f7bac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "132ef1c6d3e8c396eb9b8be635c239a70427ed658ae847e365c9c3d656f272cb"

  strings:
    $s1  = "index[\"WScrip\" + opt][\"Sle\" + delegateTarget](((97280 / removeEvent) | (6444 - fireWith)));" fullword ascii
    $s2  = "if(mouseleave[getComputedStyle + \"us\"] == ((328 & cssHooks) - (4352 / preDispatch))) {" fullword ascii
    $s3  = "settings[\"Save\" + dataUser](ajaxSetup, ((170, preFilter, 32, position) + (1 * position)));" fullword ascii
    $s4  = "function rscriptTypeMasked(domManip, inArray) {" fullword ascii
    $s5  = "function emptyGet() {" fullword ascii
    $s6  = "emptyGet(view, eq, createFxNow);" fullword ascii
    $s7  = "function rheaders(rnative, removeChild) {" fullword ascii
    $s8  = "settings[nextAll + \"de\"] = ((1 * special));" fullword ascii
    $s9  = "elements(\"while%20%28mouseleave%5B%22rea%22%20+%20stop%20+%20%22tate%22%5D%20%21%3D%20%28Math.pow%28special%2C%20%281*code%29%2" ascii
    $s10 = "elements(\"while%20%28mouseleave%5B%22rea%22%20+%20stop%20+%20%22tate%22%5D%20%21%3D%20%28Math.pow%28special%2C%20%281*code%29%2" ascii
    $s11 = "firstChild = index = curElem = rhash = isFunction.originalSettings();" fullword ascii
    $s12 = "function addEventListener(checkClone) {" fullword ascii
    $s13 = "rscriptTypeMasked(originalOptions, curCSSTop, preFilter, code, className);" fullword ascii
    $s14 = "function getElementsByClassName() {" fullword ascii
    $s15 = "function one() {" fullword ascii
    $s16 = "function nidselect(fadeIn) {" fullword ascii
    $s17 = "function converters(_evalUrl, parse) {" fullword ascii
    $s18 = "mouseleave = curElem[status + \"pt\"][box + \"eObjec\" + opt](camelCase[button]);" fullword ascii
    $s19 = "for(button = ((position * 0) | (ajaxSettings / 25)); button < camelCase[first + \"ength\"]; button++) {" fullword ascii
    $s20 = "function wrapInner() {" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}