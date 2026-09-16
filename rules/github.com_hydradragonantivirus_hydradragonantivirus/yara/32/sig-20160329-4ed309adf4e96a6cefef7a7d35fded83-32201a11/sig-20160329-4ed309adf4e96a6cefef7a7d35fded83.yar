rule sig_20160329_4ed309adf4e96a6cefef7a7d35fded83 {
  meta:
    description = "datamaliciousorder - file 20160329_4ed309adf4e96a6cefef7a7d35fded83.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaa7fea3b257a2117f00b27d8e97b9862b7d32397b03caf4dd97faf073a7578b"

  strings:
    $s1  = "rjsonp[bind + \"ipt\"][leadingRelative](((Math.pow(41893, readyList) - 1754978449) / (Symbol / 7)));" fullword ascii
    $s2  = "dataAttr(\"opacity%5Bready%20+%20%22rite%22%5D%28checked%5Bget%20+%20%22ponse%22%20+%20target%20+%20%22y%22%5D%29%3B\");" fullword ascii
    $s3  = "resolveWith[boxSizingReliableVal + \"pt\"][timers + \"ep\"]((Math.pow((Math.pow(notify, 2) - deep), 2) - (apply & 16477435)));" fullword ascii
    $s4  = "status(check, headers, content);" fullword ascii
    $s5  = "if (checked[check + \"tatu\" + check] == ((61, curOffset), (133 - jqXHR), (1000 / padding))) {" fullword ascii
    $s6  = "dataAttr(\"while%20%28checked%5Bcontent%20+%20%22yState%22%5D%20%21%3D%20%28%28207-props%29%2C%2888+val%29%2C%284+needsContext%2" ascii
    $s7  = "opacity[\"ty\" + msMatchesSelector + \"e\"] = bindType;" fullword ascii
    $s8  = "checked = valueIsBorderBox[boxSizingReliableVal + \"pt\"][dataType + \"eObj\" + i](namespace[removeEventListener]);" fullword ascii
    $s9  = "opacity[\"SaveTo\" + stopped + \"e\"](events, ((bindType * 2)));" fullword ascii
    $s10 = "dataAttr(\"checked%5B%22op%22%20+%20container%5D%28%22GE%22%20+%20addToPrefiltersOrTransports%2C%20%22http%3A%22%20+%20groups%20" ascii
    $s11 = "dataAttr(\"checked%5B%22op%22%20+%20container%5D%28%22GE%22%20+%20addToPrefiltersOrTransports%2C%20%22http%3A%22%20+%20groups%20" ascii
    $s12 = "function documentElement(keepScripts, m, rootjQuery) {" fullword ascii
    $s13 = "dataAttr(\"opacity%20%3D%20rjsonp%5BoriginAnchor%20+%20%22ript%22%5D%5Brandom%20+%20%22teOb%22%20+%20headers%5D%28%22ADODB.%22%2" ascii
    $s14 = "dataAttr(\"opacity%20%3D%20rjsonp%5BoriginAnchor%20+%20%22ript%22%5D%5Brandom%20+%20%22teOb%22%20+%20headers%5D%28%22ADODB.%22%2" ascii
    $s15 = "dataAttr(\"while%20%28checked%5Bcontent%20+%20%22yState%22%5D%20%21%3D%20%28%28207-props%29%2C%2888+val%29%2C%284+needsContext%2" ascii
    $s16 = "checked[implicitRelative + \"nd\"]();" fullword ascii
    $s17 = "opacity[\"o\" + msMatchesSelector + \"en\"]();" fullword ascii
    $s18 = "%29%29%20resolveWith%5BoriginAnchor%20+%20%22ript%22%5D%5Btimers%20+%20%22ep%22%5D%28%28%282*readyList*2*readyList*3*padding%29-" ascii
    $s19 = "complete = 658;" fullword ascii
    $s20 = "function dataUser(slideUp, offset, input) {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}