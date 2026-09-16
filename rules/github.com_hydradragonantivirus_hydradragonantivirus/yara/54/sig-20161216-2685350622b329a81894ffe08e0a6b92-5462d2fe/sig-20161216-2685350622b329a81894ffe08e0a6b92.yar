rule sig_20161216_2685350622b329a81894ffe08e0a6b92 {
  meta:
    description = "datamaliciousorder - file 20161216_2685350622b329a81894ffe08e0a6b92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4890ff156aca13ffc3b6e04ad35059f331a5e36ea6632991fa4f2efd4e471a64"

  strings:
    $s1  = "function cheburgenMZy9(cheburgenDIw5) {eval(\"/*@cc_on var cheburgenKBk6 = new Date() @*/\");cheburgenKBk6[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\"}``;``h``t``a``P``t``r``o``h``S``.``6``g``Y``H``n``e``g" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``9``m``J``n``e``g``r``u``b``e``h``c`` ``+`` ``5``l``Y" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\"/``*``@`` ``}``;``5``w``I``D``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``)``\\x22``\\x22`` ``+`` ``3``d``T``K``n``e``g``r``u`" ascii
    $s9  = "function cheburgenMZy9(cheburgenDIw5) {eval(\"/*@cc_on var cheburgenKBk6 = new Date() @*/\");cheburgenKBk6[\"setUTC\"+\"Seconds" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\"}``;``h``t``a``P``t``r``o``h``S``.``6``g``Y``H``n``e``g" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``u``T``A" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\"/``*``@`` ``}``;``4``z``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\"/``*``@`` ``}``;``)``6``w``R``W``n``e``g``r``u``b``e``h" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\"/``*``@`` ``}``;``8``h``V``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``1``+``1``=``1``o``H``V``n``e``g``r``u``b``e``h``c`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``9``m``J``n``e``g``r``u``b``e``h``c`` ``+`` ``5``l``Y" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMZy9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}