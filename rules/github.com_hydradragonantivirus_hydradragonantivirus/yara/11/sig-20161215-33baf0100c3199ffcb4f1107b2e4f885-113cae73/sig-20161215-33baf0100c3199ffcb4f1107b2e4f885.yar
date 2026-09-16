rule sig_20161215_33baf0100c3199ffcb4f1107b2e4f885 {
  meta:
    description = "datamaliciousorder - file 20161215_33baf0100c3199ffcb4f1107b2e4f885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d426be38d6ccfb9289123a268c7b614cbc8e3cd3bf7c3820df877f4b1f12cb82"

  strings:
    $s1  = "function cheburgenXFc2(cheburgenJKt3) {eval(\"/*@cc_on var cheburgenATu0 = new Date() @*/\");cheburgenATu0[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\"}``;``h``t``a``P``t``r``o``h``S``.``8``s``X``n``e``g``r" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``l``W``B``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``0`` ``=`` ``5``g``C``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s5  = "function cheburgenXFc2(cheburgenJKt3) {eval(\"/*@cc_on var cheburgenATu0 = new Date() @*/\");cheburgenATu0[\"setUTC\"+\"Seconds" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``0`` ``=`` ``5``g``C``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``r``I``T" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\"/``*``@`` ``}``;``9``l``Y``T``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``)``\\x22``x``i``u``s``c``/``m``o``c``.``u``o``g``i``" ascii
    $s14 = "turn cheburgenTYl9[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\"/``*``@`` ``}``;``3``t``K``J``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\"/``*``@`` ``}``;``3``t``K``J``n``e``g``r``u``b``e``h``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFc2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}