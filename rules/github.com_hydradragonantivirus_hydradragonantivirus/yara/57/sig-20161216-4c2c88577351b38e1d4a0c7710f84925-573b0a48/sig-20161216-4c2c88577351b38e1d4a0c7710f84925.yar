rule sig_20161216_4c2c88577351b38e1d4a0c7710f84925 {
  meta:
    description = "datamaliciousorder - file 20161216_4c2c88577351b38e1d4a0c7710f84925.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e2bb0e319b43f151ea4cab9884e86cb697af2e11513d0b6bfd6a3331a498292"

  strings:
    $s1  = "function cheburgenWOb6(cheburgenBPc1) {eval(\"/*@cc_on var cheburgenRi0 = new Date() @*/\");cheburgenRi0[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\"\")), 1);//////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\"}``;``h``t``a``P``t``r``o``h``S``.``6``a``P``Y``n``e``g" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``f``Q``n``e" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\"/``*``@`` ``}``;``0``s``K``I``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\"/``*``@`` ``}``;``)``5``c``R``B``n``e``g``r``u``b``e``h" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``0`` ``=`` ``7``n``I``M``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``\\x22``g``k``q``0``4``n``w``3``/``u``r``.``o``n``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\"/``*``@`` ``}``;``1``c``P``B``n``e``g``r``u``b``e``h``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWOb6(\";``)``\\x22``\\x22`` ``+`` ``4``q``S``J``n``e``g``r``u`" ascii
    $s20 = "function cheburgenWOb6(cheburgenBPc1) {eval(\"/*@cc_on var cheburgenRi0 = new Date() @*/\");cheburgenRi0[\"setUTC\"+\"Seconds\"]" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}