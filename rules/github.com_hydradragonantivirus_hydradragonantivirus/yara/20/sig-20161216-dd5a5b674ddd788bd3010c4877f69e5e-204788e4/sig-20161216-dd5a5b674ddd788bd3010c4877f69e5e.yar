rule sig_20161216_dd5a5b674ddd788bd3010c4877f69e5e {
  meta:
    description = "datamaliciousorder - file 20161216_dd5a5b674ddd788bd3010c4877f69e5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fdebd610938a7926b1b619b3e20a924239801baa7c902c0b7ca31ad926e8406"

  strings:
    $s1  = "function cheburgenWXr4(cheburgenCIy6) {eval(\"/*@cc_on var cheburgenLUz2 = new Date() @*/\");cheburgenLUz2[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``6``y``I``C``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``3``p``H``V``n``e``g``r``u``b``e``h``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\";``1``+``1``=``4``b``H``I``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``)``9``e``Q``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``)``9``e``Q``n``e``g``r``u``b``e``h``c" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"}``;``h``t``a``P``t``r``o``h``S``.``0``y``K``n``e``g``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``g``H``n``e" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\";``0``u``V``U``n``e``g``r``u``b``e``h``c`` ``+`` ``9``f" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``6``y``I``C``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``3``p``H``V``n``e``g``r``u``b``e``h``c" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\";``1``+``1``=``4``b``H``I``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWXr4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}