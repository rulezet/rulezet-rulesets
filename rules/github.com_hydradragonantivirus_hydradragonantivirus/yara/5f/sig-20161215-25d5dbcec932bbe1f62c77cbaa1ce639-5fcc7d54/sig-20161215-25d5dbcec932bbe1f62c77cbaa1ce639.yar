rule sig_20161215_25d5dbcec932bbe1f62c77cbaa1ce639 {
  meta:
    description = "datamaliciousorder - file 20161215_25d5dbcec932bbe1f62c77cbaa1ce639.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "223813cd7f7da4767c53654555225ee8018dc709cdc84a601910fb74bea16d55"

  strings:
    $s1  = "function cheburgenKQs6(cheburgenAo1) {eval(\"/*@cc_on var cheburgenSDi3 = new Date() @*/\");cheburgenSDi3[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\"/``*``@`` ``}``;``5``w``N``J``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``)``\\x22``\\x22`` ``+`` ``1``p``N``n``e``g``r``u``b`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\"/``*``@`` ``}``;``1``o``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\"/``*``@`` ``}``;``1``o``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "n cheburgenSh8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s16 = "function cheburgenKQs6(cheburgenAo1) {eval(\"/*@cc_on var cheburgenSDi3 = new Date() @*/\");cheburgenSDi3[\"setUTC\"+\"Seconds\"" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\"/``*``@`` ``}``;``8``h``S``n``e``g``r``u``b``e``h``c`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKQs6(\"}``;``h``t``a``P``t``r``o``h``S``.``7``u``P``n``e``g``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}