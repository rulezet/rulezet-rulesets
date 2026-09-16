rule sig_20161216_4089181e376c0f1b6170fd48cd4050f8 {
  meta:
    description = "datamaliciousorder - file 20161216_4089181e376c0f1b6170fd48cd4050f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b6e22f9f4bf2bf9bce8f25350938c7d81eb46de223e9cb7d1372ee996ea8652"

  strings:
    $s1  = "function cheburgenXZc9(cheburgenODe4) {eval(\"/*@cc_on var cheburgenYe4 = new Date() @*/\");cheburgenYe4[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\"/``*``@`` ``}``;``4``q``H``Q``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\"/``*``@`` ``}``;``5``g``U``C``n``e``g``r``u``b``e``h``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``)``\\x22``g``k``q``0``4``n``w``3``/``u``r``.``o``n``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``0`` ``=`` ``6``e``T``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\"/``*``@`` ``}``;``4``e``D``O``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``" ascii
    $s10 = "n cheburgenCUg5[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``1``+``1``=``7``h``E``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\"}``;``h``t``a``P``t``r``o``h``S``.``0``d``X``Y``n``e``g" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\"/``*``@`` ``}``;``)``3``d``I``n``e``g``r``u``b``e``h``c" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\"/``*``@`` ``}``;``4``q``H``Q``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXZc9(\";``4``j``O``R``n``e``g``r``u``b``e``h``c`` ``+`` ``7``h" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}