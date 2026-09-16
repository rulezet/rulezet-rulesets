rule sig_20161216_b56ebde5b0f5e0e2d3f43d0d5a77ed49 {
  meta:
    description = "datamaliciousorder - file 20161216_b56ebde5b0f5e0e2d3f43d0d5a77ed49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a391f5488e3870a78f7f013382a287227dad0a0fe8508540680a93e4dd0ed35"

  strings:
    $s1  = "20\");if (cheburgenLg8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenKXm6 = cheburgenDWz6[\"split\"](\"``" ascii
    $s2  = "function cheburgenOn8(cheburgenDWz6) {eval(\"/*@cc_on var cheburgenLg8 = new Date() @*/\");cheburgenLg8[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``l" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\"/``*``@`` ``}``;``6``z``W``D``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``b``V``n`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``i" ascii
    $s9  = "function cheburgenOn8(cheburgenDWz6) {eval(\"/*@cc_on var cheburgenLg8 = new Date() @*/\");cheburgenLg8[\"setUTC\"+\"Seconds\"](" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\"/``*``@`` ``}``;``)``9``r``O``M``n``e``g``r``u``b``e``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``b``V``n`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\"}``;``h``t``a``P``t``r``o``h``S``.``0``v``F``M``n``e``g`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``g``H``F``n`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``1``+``1``=``9``n``A``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\"/``*``@`` ``}``;``)``9``r``O``M``n``e``g``r``u``b``e``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``)``\\x22``\\x22`` ``+`` ``0``a``Q``L``n``e``g``r``u``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOn8(\"\")), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}