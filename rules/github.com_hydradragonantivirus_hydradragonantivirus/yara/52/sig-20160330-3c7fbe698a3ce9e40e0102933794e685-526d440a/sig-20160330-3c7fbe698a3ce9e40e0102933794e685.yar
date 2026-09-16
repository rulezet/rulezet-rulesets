rule sig_20160330_3c7fbe698a3ce9e40e0102933794e685 {
  meta:
    description = "datamaliciousorder - file 20160330_3c7fbe698a3ce9e40e0102933794e685.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1d20fc35fd043b167941f67b0ab2fb555fe4d01136fcdef9153c20b934416c4"

  strings:
    $s1  = "eval(unescape([\"markFunction&20&3D&20&28&22WScrip&22&29&3Bvar&20adjusted&20&3D&20&28&22r/zFN1&22&29&2C&20type&20&3D&\", \"20&28" ascii
    $s2  = "  count(\"elems&5B&22op&22&20+&20fontWeight&5D&28&22GE&22&20+&20domManip&2C&20&22http&3A/&22&20+&20rattributeQuotes&20+&20&22gos" ascii
    $s3  = "  count(\"contextBackup&20&3D&20slideUp&5B&22Expa&22&20+&20transport&20+&20&22vironm&22&20+&20type&20+&20&22tring&22&20+&20curre" ascii
    $s4  = "  count(\"while&20&28elems&5B&22ready&22&20+&20completed&20+&20&22e&22&5D&20&21&3D&20&28Math.pow&28&281*resolveWith&29&2C&20&281" ascii
    $s5  = "      elems = curCSS[body + \"pt\"][addGetHookIf + \"Objec\" + key](mozMatchesSelector[_]);" fullword ascii
    $s6  = "  count(\"mozMatchesSelector&20&3D&20&5B&22Msx&22&20+&20rootjQuery&20+&20&22.Se&22&20+&20hookFn&20+&20&22XMLHT&22&20+&20inspect&" ascii
    $s7  = "  count(\"ready&28&22http&3A/&22&20+&20rattributeQuotes&20+&20&22gostos&22&20+&20w&20+&20&22.br/zF&22&20+&20tweens&20+&20&22xe&2" ascii
    $s8  = "  count(\"ready&28&22http&3A/&22&20+&20rattributeQuotes&20+&20&22gostos&22&20+&20w&20+&20&22.br/zF&22&20+&20tweens&20+&20&22xe&2" ascii
    $s9  = "  count(\"while&20&28elems&5B&22ready&22&20+&20completed&20+&20&22e&22&5D&20&21&3D&20&28Math.pow&28&281*resolveWith&29&2C&20&281" ascii
    $s10 = "function prevUntil(propFix, postDispatch, returnValue) {" fullword ascii
    $s11 = "function identifier() {" fullword ascii
    $s12 = "function tokenize() {" fullword ascii
    $s13 = "      fn(writable, booleans, completed, getBoundingClientRect, inspect);" fullword ascii
    $s14 = "  count(\"elementMatchers&5Bbody&20+&20&22pt&22&5D&5Bdisabled&20+&20&22eep&22&5D&28&28&285*rhash*5*resolveWith*2*writable*2*writ" ascii
    $s15 = "  count(\"elems&5B&22op&22&20+&20fontWeight&5D&28&22GE&22&20+&20domManip&2C&20&22http&3A/&22&20+&20rattributeQuotes&20+&20&22gos" ascii
    $s16 = "function count(dirruns) {" fullword ascii
    $s17 = "&2C&20easing&20&3D&20&28&22Sle&22&29&3Bvar&20fontWeight&20&3D&20&28f\", \"unction&20xml&28&29&7B&7D&2C&20&22en&22&29&2C&20rootjQ" ascii
    $s18 = "  count(\"mozMatchesSelector&20&3D&20&5B&22Msx&22&20+&20rootjQuery&20+&20&22.Se&22&20+&20hookFn&20+&20&22XMLHT&22&20+&20inspect&" ascii
    $s19 = "  count(\"contextBackup&20&3D&20slideUp&5B&22Expa&22&20+&20transport&20+&20&22vironm&22&20+&20type&20+&20&22tring&22&20+&20curre" ascii
    $s20 = "function attrHooks(augmentWidthOrHeight, createComment) {" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}