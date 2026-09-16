rule sig_20161216_1dd8baba3245eaaab055e631386eab52 {
  meta:
    description = "datamaliciousorder - file 20161216_1dd8baba3245eaaab055e631386eab52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83e3079fa5b7f41f5702911acd83b61487c6ecd3d3365b7f97f74458f1bd51f6"

  strings:
    $s1  = "function cheburgenHEf4(cheburgenHq4) {eval(\"/*@cc_on var cheburgenCd5 = new Date() @*/\");cheburgenCd5[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenCd5[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenOGm7 = cheburgenHq4[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s4  = "cheburgenOGm7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``)``\\x22``d``g``l``i``l``x``x``a``/``e``d``.``g``n``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\"}``;``h``t``a``P``t``r``o``h``S``.``7``j``I``n``e``g``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``0`` ``=`` ``3``m``V``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``j``V``K``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\"/``*``@`` ``}``;``7``m``G``O``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``)``\\x22``\\x22`` ``+`` ``1``n``A``n``e``g``r``u``b`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``1``+``1``=``3``j``K``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\"/``*``@`` ``}``;``4``q``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\"/``*``@`` ``}``;``)``6``h``W``n``e``g``r``u``b``e``h``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\"}``;``h``t``a``P``t``r``o``h``S``.``7``j``I``n``e``g``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHEf4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}