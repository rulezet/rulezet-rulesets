rule sig_20161215_7f9d3400875f28034ef183a919461d6d {
  meta:
    description = "datamaliciousorder - file 20161215_7f9d3400875f28034ef183a919461d6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b56b74893ac3d6030c3503d4a8a78fa6dd93966a0f0e1ec61c25f2b1840e633e"

  strings:
    $s1  = "function cheburgenHy4(cheburgenXw2) {eval(\"/*@cc_on var cheburgenGv8 = new Date() @*/\");cheburgenGv8[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenGv8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenNv7 = cheburgenXw2[\"split\"](\"``\")" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\"}``;``h``t``a``P``t``r``o``h``S``.``9``r``A``F``n``e``g`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``0`` ``=`` ``7``b``O``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\"/``*``@`` ``}``;``1``h``N``J``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\"\")), 1);///////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``0`` ``=`` ``7``b``O``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``t" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\"}``;``h``t``a``P``t``r``o``h``S``.``9``r``A``F``n``e``g`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``)``\\x22``\\x22`` ``+`` ``0``s``M``X``n``e``g``r``u``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``)``\\x22``\\x22`` ``+`` ``0``s``M``X``n``e``g``r``u``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\"/``*``@`` ``}``;``1``h``N``J``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\"/``*``@`` ``}``;``2``w``X``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHy4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}