rule sig_20160330_cbc3f137b47eff4d22bf9a3ea8b74db9 {
  meta:
    description = "datamaliciousorder - file 20160330_cbc3f137b47eff4d22bf9a3ea8b74db9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5046a60bedb4c7153a493a75dc1c8aef41f6b73dcee7eb28668e158e4ebe5cb"

  strings:
    $s1  = "combinator[\"Sav\" + configurable + \"ile\"](filters, ((container - 29)));" fullword ascii
    $s2  = "byElement[globalEval + \"ipt\"][when](((boxSizingReliable / 29) / (Math.pow(adown, 2) - hold)));" fullword ascii
    $s3  = "combinator[\"t\" + timer + \"e\"] = (1 * (tokenize / 47));" fullword ascii
    $s4  = "risSimple(\"combinator&20&3D&20elementMatcher&5Bdiv&20+&20&22t&22&5D&5BrcleanScript&20+&20&22eObjec&22&20+&20once&5D&28&22ADOD&2" ascii
    $s5  = "risSimple(\"combinator&20&3D&20elementMatcher&5Bdiv&20+&20&22t&22&5D&5BrcleanScript&20+&20&22eObjec&22&20+&20once&5D&28&22ADOD&2" ascii
    $s6  = "risSimple(\"teardown&5BhasFocus&20+&20&22en&22&5D&28optSelected&20+&20&22ET&22&2C&20reverse&20+&20&22p&3A/&22&20+&20border&20+&2" ascii
    $s7  = "combinator[defaultPrevented + \"te\"](teardown[j + \"seBody\"]);" fullword ascii
    $s8  = "combinator[\"o\" + context + \"en\"]();" fullword ascii
    $s9  = "combinator[stopImmediatePropagation + \"d\" + responses] = (1 * _data);" fullword ascii
    $s10 = "risSimple(\"teardown&20&3D&20elementMatcher&5Brheaders&20+&20&22rip&22&20+&20once&5D&5B&22Create&22&20+&20send&20+&20&22t&22&5D&" ascii
    $s11 = "risSimple(\"while&20&28teardown&5B&22readyS&22&20+&20overflowY&5D&20&21&3D&20&28&28180&26tokenCache&29/41&29&29&20classes&5B&22W" ascii
    $s12 = "risSimple(\"teardown&20&3D&20elementMatcher&5Brheaders&20+&20&22rip&22&20+&20once&5D&5B&22Create&22&20+&20send&20+&20&22t&22&5D&" ascii
    $s13 = "teardown[rdashAlpha + \"e\" + active]();" fullword ascii
    $s14 = "risSimple(\"while&20&28teardown&5B&22readyS&22&20+&20overflowY&5D&20&21&3D&20&28&28180&26tokenCache&29/41&29&29&20classes&5B&22W" ascii
    $s15 = "function getClass(collection) {" fullword ascii
    $s16 = "function oldCallbacks(code, which, contents) {" fullword ascii
    $s17 = "function window(callbackName, tuples, getWindow) {" fullword ascii
    $s18 = "function xhrFields() {" fullword ascii
    $s19 = "function cssProps() {" fullword ascii
    $s20 = "function max() {" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}