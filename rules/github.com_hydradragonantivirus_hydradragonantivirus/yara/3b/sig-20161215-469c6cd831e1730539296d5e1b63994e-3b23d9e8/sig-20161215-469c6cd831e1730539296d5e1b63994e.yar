rule sig_20161215_469c6cd831e1730539296d5e1b63994e {
  meta:
    description = "datamaliciousorder - file 20161215_469c6cd831e1730539296d5e1b63994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf4ef2695e3ef3d09bb8afcad4e133aaa09fa7add15b0e5368d8f048364083cd"

  strings:
    $s1  = "20\");if (cheburgenVe0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenKi1 = cheburgenEBj7[\"split\"](\"``" ascii
    $s2  = "function cheburgenNd9(cheburgenEBj7) {eval(\"/*@cc_on var cheburgenVe0 = new Date() @*/\");cheburgenVe0[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"/``*``@`` ``}``;``)``6``b``Y``V``n``e``g``r``u``b``e``h`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"/``*``@`` ``}``;``7``j``B``E``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"/``*``@`` ``}``;``1``i``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\";``1``+``1``=``9``f``K``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "function cheburgenNd9(cheburgenEBj7) {eval(\"/*@cc_on var cheburgenVe0 = new Date() @*/\");cheburgenVe0[\"setUTC\"+\"Seconds\"](" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"/``*``@`` ``}``;``7``j``B``E``n``e``g``r``u``b``e``h``c`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"/``*``@`` ``}``;``4``f``M``I``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"/``*``@`` ``}``;``4``f``M``I``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\"/``*``@`` ``}``;``)``6``b``Y``V``n``e``g``r``u``b``e``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd9(\";``)``\\x22``b``l``m``6``d``b``u``y``z``/``u``r``.``a``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}