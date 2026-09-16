rule sig_20160330_9289961cf3e8c6b58fefd8a45e921989 {
  meta:
    description = "datamaliciousorder - file 20160330_9289961cf3e8c6b58fefd8a45e921989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "008119daf0696dac8e80cf72494ea72175d5e9a6f8fdfdb7fdcad5c2bffeb5a6"

  strings:
    $x1  = "eval(unescape([\"bind&20&3D&20&284&29&3B&20rtrim&20&3D&20&284569&29&3B&20protocol&20&3D&20&28&22T&22&29&3Bvar&20escap\", \"ed&20" ascii
    $s2  = "        reliableMarginLeft[\"Sav\" + complete + \"e\"](hasScripts, ((32 - scrollTo) | 0));" fullword ascii
    $s3  = "        qualifier[attrHooks + \"u\" + host](hasScripts);" fullword ascii
    $s4  = "    for(nidselect = (inArray * (1 * merge)); nidselect < off[\"l\" + currentTarget + \"h\"]; nidselect++) {" fullword ascii
    $s5  = "function method(mimeType, xhrSupported, scriptCharset) {" fullword ascii
    $s6  = "function condense(removeAttribute, propName, postMap) {" fullword ascii
    $s7  = "function dequeue(ajaxSetup, rheader) {" fullword ascii
    $s8  = "function transports(v) {" fullword ascii
    $s9  = "all = div1 = conv = sort = parseOnly.css();" fullword ascii
    $s10 = "    transports(\"while&20&28xml&5Barr&20+&20&22ySt&22&20+&20winnow&5D&20&21&3D&20&28&284&7Cbind&29&7C&28253&2Cmerge&29&29&29&20s" ascii
    $s11 = "    transports(\"qualifier&20&3D&20conv&5B&22WScrip&22&20+&20preFilters&5D&5B&22Creat&22&20+&20compiled&20+&20&22ct&22&5D&28offs" ascii
    $s12 = "function attr() {" fullword ascii
    $s13 = "function jsonp(args) {" fullword ascii
    $s14 = "condense(finish);" fullword ascii
    $s15 = "replace(/&/g, '%'));" fullword ascii
    $s16 = "function attributes(each, cssFn, srcElements) {" fullword ascii
    $s17 = "    transports(\"while&20&28xml&5Barr&20+&20&22ySt&22&20+&20winnow&5D&20&21&3D&20&28&284&7Cbind&29&7C&28253&2Cmerge&29&29&29&20s" ascii
    $s18 = "function bubbleType(removeData, preMap) {" fullword ascii
    $s19 = "function namespaces(cssFn, udataOld, match) {" fullword ascii
    $s20 = "    if(xml[finish + \"tus\"] == ((event * 2 + isArray) | (4 * nType))) {" fullword ascii

  condition:
    uint16(0) == 0x666f and
    1 of ($x*) and 4 of them
}