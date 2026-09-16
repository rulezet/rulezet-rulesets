rule sig_20161216_7e01fd97baab10de89637514f07ca592 {
  meta:
    description = "datamaliciousorder - file 20161216_7e01fd97baab10de89637514f07ca592.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "211b99dde08dfb1dda1dce4ab027e350aaf553e59c0019d4f5bbbf3ea9b1061e"

  strings:
    $s1  = "function cheburgenTRw6(cheburgenZCp1) {eval(\"/*@cc_on var cheburgenTMg2 = new Date() @*/\");cheburgenTMg2[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``" ascii
    $s3  = "urn cheburgenXs3[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\"}``;``h``t``a``P``t``r``o``h``S``.``6``n``G``Q``n``e``g" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``)``\\x22``\\x22`` ``+`` ``1``j``U``L``n``e``g``r``u`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\"}``;``h``t``a``P``t``r``o``h``S``.``6``n``G``Q``n``e``g" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\"/``*``@`` ``}``;``1``p``C``Z``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``)``\\x22``\\x22`` ``+`` ``1``j``U``L``n``e``g``r``u`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\"\")), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``0`` ``=`` ``2``m``R``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s16 = "function cheburgenTRw6(cheburgenZCp1) {eval(\"/*@cc_on var cheburgenTMg2 = new Date() @*/\");cheburgenTMg2[\"setUTC\"+\"Seconds" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``s``K``n``e" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTRw6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}