rule sig_20161215_c6c4df1bcffea236215f8662b40c5c62 {
  meta:
    description = "datamaliciousorder - file 20161215_c6c4df1bcffea236215f8662b40c5c62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24e5c25c5785079dbfa200323a8ccf086129df9bf89a3653d49ea6082d118152"

  strings:
    $s1  = "20\");if (cheburgenXs7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenMh5 = cheburgenIPj5[\"split\"](\"``" ascii
    $s2  = "function cheburgenNy1(cheburgenIPj5) {eval(\"/*@cc_on var cheburgenXs7 = new Date() @*/\");cheburgenXs7[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\"/``*``@`` ``}``;``5``h``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\"/``*``@`` ``}``;``8``l``H``T``n``e``g``r``u``b``e``h``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\"}``;``h``t``a``P``t``r``o``h``S``.``0``k``Q``V``n``e``g`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``)``\\x22``\\x22`` ``+`` ``2``h``J``n``e``g``r``u``b``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``r``Y``I`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\"\")), 1);///////////////////////////////////////////////" ascii
    $s13 = "function cheburgenNy1(cheburgenIPj5) {eval(\"/*@cc_on var cheburgenXs7 = new Date() @*/\");cheburgenXs7[\"setUTC\"+\"Seconds\"](" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``)``\\x22``g``k``q``0``4``n``w``3``/``u``r``.``o``n``i" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\"/``*``@`` ``}``;``5``j``P``I``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``0`` ``=`` ``3``k``N``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNy1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}