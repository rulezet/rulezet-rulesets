rule sig_20160328_bb7507eafafb4d9282a289a42d5e511e {
  meta:
    description = "datamaliciousorder - file 20160328_bb7507eafafb4d9282a289a42d5e511e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "855866341d2c3b12eeb04eba24b9c5817d2b49e29e879f1e853c4543778e12fd"

  strings:
    $s1  = "    while(postSelector[evt + \"ySta\" + textContent] != ((max + 28) / (Math.pow(globalEval, 2) - letterSpacing))) prop[\"WScrip" ascii
    $s2  = "text = prop = isFunction = getById = rscriptType.host();" fullword ascii
    $s3  = "    while(postSelector[evt + \"ySta\" + textContent] != ((max + 28) / (Math.pow(globalEval, 2) - letterSpacing))) prop[\"WScrip" ascii
    $s4  = "detach][\"Sleep\"]((32, (refElements), (64 | iterator), (Math.pow(60, camelCase) - 3500)));" fullword ascii
    $s5  = "    if(postSelector[rclass] == ((isLocal * 2 + selected) * (19 - toggleClass) + 10)) {" fullword ascii
    $s6  = "        isFunction[jqXHR + \"ipt\"][realStringObj](((Math.pow(status, 2) - input) & (7808 | optSelected)));" fullword ascii
    $s7  = "hover%20+%20%22uctor%22%5D%5Btraditional%20+%20%22ype%22%5D%5BgetJSON%20+%20%22o%22%20+%20which%5D%5B%22app%22%20+%20getAttribut" ascii
    $s8  = "function border(hasContent) {" fullword ascii
    $s9  = "    contextBackup(parseXML(\"interval%20%3D%20%5Bfunescape%20+%20%222.Ser%22%20+%20attaches%20+%20%22HTTP.%22%20+%20identifier%2" ascii
    $s10 = "function head(_) {" fullword ascii
    $s11 = "lastChild[\"m\" + firing + \"e\"] = (99, hookFn, 248, _data);" fullword ascii
    $s12 = "speed(token, show, clearCloneStyle, removeChild);" fullword ascii
    $s13 = "function tokenize(pseudo) {" fullword ascii
    $s14 = "function _queueHooks() {" fullword ascii
    $s15 = "function has() {" fullword ascii
    $s16 = "function docElem() {" fullword ascii
    $s17 = "function pdataOld() {" fullword ascii
    $s18 = "function remove(animated, s, find) {" fullword ascii
    $s19 = "function parseXML(rfocusable) {" fullword ascii
    $s20 = "remove(elemData);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}