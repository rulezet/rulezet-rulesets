rule sig_20161216_fecf4f062d8ec2a4e7c2358f4ebd66b0 {
  meta:
    description = "datamaliciousorder - file 20161216_fecf4f062d8ec2a4e7c2358f4ebd66b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76abef055622d57645a770618f57903bec82e9f7b626e0976945527506163629"

  strings:
    $s1  = "function cheburgenYb2(cheburgenRSq0) {eval(\"/*@cc_on var cheburgenQPn5 = new Date() @*/\");cheburgenQPn5[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\"/``*``@`` ``}``;``)``0``k``R``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\"/``*``@`` ``}``;``0``q``S``R``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``z``D``n`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``0`` ``=`` ``9``n``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\"/``*``@`` ``}``;``5``j``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``4``y``B``C``n``e``g``r``u``b``e``h``c`` ``+`` ``4``b`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\"/``*``@`` ``}``;``5``j``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``)``\\x22``\\x22`` ``+`` ``2``j``O``n``e``g``r``u``b``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "function cheburgenYb2(cheburgenRSq0) {eval(\"/*@cc_on var cheburgenQPn5 = new Date() @*/\");cheburgenQPn5[\"setUTC\"+\"Seconds\"" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYb2(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}