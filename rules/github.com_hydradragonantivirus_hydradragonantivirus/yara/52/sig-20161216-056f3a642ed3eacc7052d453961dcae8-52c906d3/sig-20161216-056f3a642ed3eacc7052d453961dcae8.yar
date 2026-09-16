rule sig_20161216_056f3a642ed3eacc7052d453961dcae8 {
  meta:
    description = "datamaliciousorder - file 20161216_056f3a642ed3eacc7052d453961dcae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d0f5da15812c44d64f6dc94867ec0b166733c320f94bacc18aee2fb76705fc1"

  strings:
    $s1  = "function cheburgenZAw8(cheburgenCQt4) {eval(\"/*@cc_on var cheburgenFIk3 = new Date() @*/\");cheburgenFIk3[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``1``q``D``J``n``e``g``r``u``b``e``h``c`` ``+`` ``0``w" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``)``\\x22``\\x22`` ``+`` ``9``k``R``K``n``e``g``r``u`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\"/``*``@`` ``}``;``4``y``N``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``j``G``W``n" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s8  = "function cheburgenZAw8(cheburgenCQt4) {eval(\"/*@cc_on var cheburgenFIk3 = new Date() @*/\");cheburgenFIk3[\"setUTC\"+\"Seconds" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\"}``;``h``t``a``P``t``r``o``h``S``.``8``s``X``Z``n``e``g" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``1``q``D``J``n``e``g``r``u``b``e``h``c`` ``+`` ``0``w" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``)``\\x22``\\x22`` ``+`` ``9``k``R``K``n``e``g``r``u`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``)``\\x22``6``g``c``g``6``/``e``d``.``c``i``s``u``m``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\"/``*``@`` ``}``;``)``6``s``Q``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``0`` ``=`` ``3``u``O``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\"\")), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\";``)``\\x22``6``g``c``g``6``/``e``d``.``c``i``s``u``m``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZAw8(\"\")), 1);//////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}