rule sig_20161216_48e13f2be1710f86f92e14672ac66636 {
  meta:
    description = "datamaliciousorder - file 20161216_48e13f2be1710f86f92e14672ac66636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "112e51d9170716638eb547ca4bbb63198eacd8ab5cdee5dc0be9b7f4590e6a3e"

  strings:
    $s1  = "function cheburgenCBs1(cheburgenSCl4) {eval(\"/*@cc_on var cheburgenYVh3 = new Date() @*/\");cheburgenYVh3[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\"/``*``@`` ``}``;``4``l``C``S``n``e``g``r``u``b``e``h``c" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\"}``;``h``t``a``P``t``r``o``h``S``.``9``r``L``n``e``g``r" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``1``+``1``=``9``g``R``U``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "function cheburgenCBs1(cheburgenSCl4) {eval(\"/*@cc_on var cheburgenYVh3 = new Date() @*/\");cheburgenYVh3[\"setUTC\"+\"Seconds" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\"/``*``@`` ``}``;``4``l``C``S``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``h``F``P``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\"/``*``@`` ``}``;``)``4``s``P``n``e``g``r``u``b``e``h``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``)``\\x22``\\x22`` ``+`` ``6``w``R``Q``n``e``g``r``u`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\"/``*``@`` ``}``;``1``b``G``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``)``\\x22``p``a``h``5``d``d``w``b``c``5``/``m``o``c``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``e``M``Y" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCBs1(\"}``;``h``t``a``P``t``r``o``h``S``.``9``r``L``n``e``g``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}