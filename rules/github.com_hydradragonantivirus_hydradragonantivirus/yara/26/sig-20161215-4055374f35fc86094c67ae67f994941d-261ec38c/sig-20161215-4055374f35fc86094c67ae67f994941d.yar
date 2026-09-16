rule sig_20161215_4055374f35fc86094c67ae67f994941d {
  meta:
    description = "datamaliciousorder - file 20161215_4055374f35fc86094c67ae67f994941d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ff64905db39499ab4fe235a2f7672bfef7156e82f03d89212844fd909762937"

  strings:
    $s1  = "function cheburgenOw5(cheburgenHXo9) {eval(\"/*@cc_on var cheburgenUNn0 = new Date() @*/\");cheburgenUNn0[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\"/``*``@`` ``}``;``)``5``a``P``V``n``e``g``r``u``b``e``h`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\"/``*``@`` ``}``;``3``m``V``X``n``e``g``r``u``b``e``h``c`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``0`` ``=`` ``8``h``X``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``1``+``1``=``7``c``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``\\x22``g``k``q``0``4``n``w``3``/``u``r``.``o``n``i" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``\\x22``\\x22`` ``+`` ``3``u``X``G``n``e``g``r``u``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\"/``*``@`` ``}``;``6``b``B``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``\\x22``\\x22`` ``+`` ``3``u``X``G``n``e``g``r``u``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``b``Z``E`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``e" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``a" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\"/``*``@`` ``}``;``9``o``X``H``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``e" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOw5(\"}``;``h``t``a``P``t``r``o``h``S``.``8``a``R``A``n``e``g`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}