rule sig_20161215_dbaab17955738111c4b68285c1d929f2 {
  meta:
    description = "datamaliciousorder - file 20161215_dbaab17955738111c4b68285c1d929f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9eaa7fcadd25129cbbd5cb9746e489285fbaeaac1c55ae46066d046e4e32884"

  strings:
    $s1  = "function cheburgenLUc8(cheburgenUBw9) {eval(\"/*@cc_on var cheburgenJLk1 = new Date() @*/\");cheburgenJLk1[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\"/``*``@`` ``}``;``9``y``A``P``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``0`` ``=`` ``3``i``P``E``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``1``+``1``=``4``j``M``M``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "function cheburgenLUc8(cheburgenUBw9) {eval(\"/*@cc_on var cheburgenJLk1 = new Date() @*/\");cheburgenJLk1[\"setUTC\"+\"Seconds" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\"\")), 1);//////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\"}``;``h``t``a``P``t``r``o``h``S``.``3``a``L``n``e``g``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\"/``*``@`` ``}``;``)``4``g``B``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``)``\\x22``\\x22`` ``+`` ``0``v``B``X``n``e``g``r``u`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\"/``*``@`` ``}``;``)``4``g``B``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``0`` ``=`` ``3``i``P``E``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\"}``;``h``t``a``P``t``r``o``h``S``.``3``a``L``n``e``g``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUc8(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}