rule sig_20161216_5416d51bfa4704b807346abfa736234b {
  meta:
    description = "datamaliciousorder - file 20161216_5416d51bfa4704b807346abfa736234b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd9ef225c51b29ad9d89f1a3a8ba908e024ecaefdf5785a3bad67e79b340e071"

  strings:
    $s1  = "0\");if (cheburgenYe0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenIs3 = cheburgenSd0[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenSe7(cheburgenSd0) {eval(\"/*@cc_on var cheburgenYe0 = new Date() @*/\");cheburgenYe0[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``l``W``n``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "eburgenIs3[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``1``+``1``=``9``l``Z``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``3``c``A``D``n``e``g``r``u``b``e``h``c`` ``+`` ``4``l`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\"/``*``@`` ``}``;``3``s``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\"/``*``@`` ``}``;``)``6``x``H``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``3``c``A``D``n``e``g``r``u``b``e``h``c`` ``+`` ``4``l`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``g" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\"/``*``@`` ``}``;``3``s``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``1``+``1``=``9``l``Z``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``g" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\";``0`` ``=`` ``3``w``N``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSe7(\"/``*``@`` ``}``;``1``q``M``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}