rule sig_20161215_6a9d82e356fcdeaf2de67a8d4ff8dfb6 {
  meta:
    description = "datamaliciousorder - file 20161215_6a9d82e356fcdeaf2de67a8d4ff8dfb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "994462a1000d746771f0c58e236502e172f231e594822cf57ea489352cbd8669"

  strings:
    $s1  = "0\");if (cheburgenEm8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenBIl4 = cheburgenQo7[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenYe7(cheburgenQo7) {eval(\"/*@cc_on var cheburgenEm8 = new Date() @*/\");cheburgenEm8[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``s" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"/``*``@`` ``}``;``3``t``A``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``1``+``1``=``6``m``I``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"}``;``h``t``a``P``t``r``o``h``S``.``8``t``Y``n``e``g``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"/``*``@`` ``}``;``4``l``I``B``n``e``g``r``u``b``e``h``c`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``." ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"}``;``h``t``a``P``t``r``o``h``S``.``8``t``Y``n``e``g``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"/``*``@`` ``}``;``)``4``f``L``n``e``g``r``u``b``e``h``c`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"/``*``@`` ``}``;``7``o``Q``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``s``Y``n`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\"/``*``@`` ``}``;``4``l``I``B``n``e``g``r``u``b``e``h``c`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYe7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}