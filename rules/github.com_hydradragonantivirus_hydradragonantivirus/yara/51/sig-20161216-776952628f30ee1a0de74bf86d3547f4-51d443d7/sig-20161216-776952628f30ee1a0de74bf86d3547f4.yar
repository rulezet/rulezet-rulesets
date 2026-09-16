rule sig_20161216_776952628f30ee1a0de74bf86d3547f4 {
  meta:
    description = "datamaliciousorder - file 20161216_776952628f30ee1a0de74bf86d3547f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8aa3e1d92f4a1708b391c0f42bd203bf52d7ed52dee45bd531f742fc3556fbb2"

  strings:
    $s1  = "function cheburgenFAc7(cheburgenPb8) {eval(\"/*@cc_on var cheburgenIGq8 = new Date() @*/\");cheburgenIGq8[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``)``\\x22``\\x22`` ``+`` ``1``n``Q``n``e``g``r``u``b`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\"/``*``@`` ``}``;``0``y``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\"/``*``@`` ``}``;``0``y``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\"}``;``h``t``a``P``t``r``o``h``S``.``4``e``C``n``e``g``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\"/``*``@`` ``}``;``)``1``w``G``F``n``e``g``r``u``b``e``h" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\"\")), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``)``\\x22``\\x22`` ``+`` ``1``n``Q``n``e``g``r``u``b`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``" ascii
    $s12 = "function cheburgenFAc7(cheburgenPb8) {eval(\"/*@cc_on var cheburgenIGq8 = new Date() @*/\");cheburgenIGq8[\"setUTC\"+\"Seconds\"" ascii
    $s13 = "rn cheburgenLBb1[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\"}``;``h``t``a``P``t``r``o``h``S``.``4``e``C``n``e``g``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``1``+``1``=``7``i``H``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFAc7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}