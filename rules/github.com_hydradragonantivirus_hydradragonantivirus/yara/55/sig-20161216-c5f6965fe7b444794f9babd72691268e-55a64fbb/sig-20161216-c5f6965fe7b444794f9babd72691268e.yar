rule sig_20161216_c5f6965fe7b444794f9babd72691268e {
  meta:
    description = "datamaliciousorder - file 20161216_c5f6965fe7b444794f9babd72691268e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85298f4efabff4db8811516caa7fe285d15be6242dbc33c34424033d076fe163"

  strings:
    $s1  = "\"20\");if (cheburgenIw7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenBh0 = cheburgenFWw0[\"split\"](\"`" ascii
    $s2  = "function cheburgenWGm8(cheburgenFWw0) {eval(\"/*@cc_on var cheburgenIw7 = new Date() @*/\");cheburgenIw7[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``)``\\x22``d``l``d``s``v``9``/``m``o``c``.``g``n``u``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\"\")), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\"}``;``h``t``a``P``t``r``o``h``S``.``0``y``Z``n``e``g``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``k``B``O" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``1``+``1``=``8``k``S``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\"/``*``@`` ``}``;``0``h``B``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\"}``;``h``t``a``P``t``r``o``h``S``.``0``y``Z``n``e``g``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s14 = "function cheburgenWGm8(cheburgenFWw0) {eval(\"/*@cc_on var cheburgenIw7 = new Date() @*/\");cheburgenIw7[\"setUTC\"+\"Seconds\"]" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\"/``*``@`` ``}``;``2``b``Q``Z``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWGm8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}