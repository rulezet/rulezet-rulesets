rule sig_20161216_eb234ee7b9c4bf28bba79d8b49d4a661 {
  meta:
    description = "datamaliciousorder - file 20161216_eb234ee7b9c4bf28bba79d8b49d4a661.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d808b146c08e811f4ddc040383f2e806f3237e0d2c1f39a5a0b9999357756333"

  strings:
    $s1  = "function cheburgenRs3(cheburgenOi6) {eval(\"/*@cc_on var cheburgenNYj5 = new Date() @*/\");cheburgenNYj5[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``j``Z``I`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``n``B``n``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``0`` ``=`` ``1``k``R``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``w" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``n``B``n``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\"}``;``h``t``a``P``t``r``o``h``S``.``9``t``W``K``n``e``g`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``\\x22``\\x22`` ``+`` ``8``z``W``n``e``g``r``u``b``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\"/``*``@`` ``}``;``3``g``P``G``n``e``g``r``u``b``e``h``c`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``\\x22``\\x22`` ``+`` ``8``z``W``n``e``g``r``u``b``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\"}``;``h``t``a``P``t``r``o``h``S``.``9``t``W``K``n``e``g`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\"/``*``@`` ``}``;``)``5``e``K``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\";``1``+``1``=``8``l``M``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRs3(\"/``*``@`` ``}``;``5``s``U``I``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}