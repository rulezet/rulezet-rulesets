rule sig_20161215_ec06e2faaae43d141732277fcb30fbec {
  meta:
    description = "datamaliciousorder - file 20161215_ec06e2faaae43d141732277fcb30fbec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a7bc159b820ad62828259f39a413b95eaf5c69b543048a4be71645c80210792"

  strings:
    $s1  = "function cheburgenELq0(cheburgenHt2) {eval(\"/*@cc_on var cheburgenKZa9 = new Date() @*/\");cheburgenKZa9[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s3  = "n cheburgenKq3[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``)``\\x22``\\x22`` ``+`` ``1``u``A``Y``n``e``g``r``u`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\"/``*``@`` ``}``;``9``p``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``i``L``T``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``1``+``1``=``5``b``W``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\"/``*``@`` ``}``;``3``q``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\"/``*``@`` ``}``;``3``q``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``)``\\x22``\\x22`` ``+`` ``1``u``A``Y``n``e``g``r``u`" ascii
    $s17 = "function cheburgenELq0(cheburgenHt2) {eval(\"/*@cc_on var cheburgenKZa9 = new Date() @*/\");cheburgenKZa9[\"setUTC\"+\"Seconds\"" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``0`` ``=`` ``4``u``G``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELq0(\"\")), 1);//////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}