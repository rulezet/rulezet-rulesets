rule sig_20161215_2a2bf02cd1b6babde9d8eddfa1326db3 {
  meta:
    description = "datamaliciousorder - file 20161215_2a2bf02cd1b6babde9d8eddfa1326db3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc4d5fd5b567d8811077c40a6015db73225124c5f9652b9e26d1691440feeae0"

  strings:
    $s1  = "20\");if (cheburgenNd9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenXSm4 = cheburgenFm5[\"split\"](\"``" ascii
    $s2  = "function cheburgenKOm0(cheburgenFm5) {eval(\"/*@cc_on var cheburgenNd9 = new Date() @*/\");cheburgenNd9[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\"/``*``@`` ``}``;``5``m``F``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``9``l``G``M``n``e``g``r``u``b``e``h``c`` ``+`` ``8``p" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``e``I``P" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\"/``*``@`` ``}``;``5``c``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "function cheburgenKOm0(cheburgenFm5) {eval(\"/*@cc_on var cheburgenNd9 = new Date() @*/\");cheburgenNd9[\"setUTC\"+\"Seconds\"](" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``1``+``1``=``9``l``L``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``9``l``G``M``n``e``g``r``u``b``e``h``c`` ``+`` ``8``p" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``0`` ``=`` ``7``a``I``N``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\"/``*``@`` ``}``;``5``m``F``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOm0(\"/``*``@`` ``}``;``)``9``x``Y``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}