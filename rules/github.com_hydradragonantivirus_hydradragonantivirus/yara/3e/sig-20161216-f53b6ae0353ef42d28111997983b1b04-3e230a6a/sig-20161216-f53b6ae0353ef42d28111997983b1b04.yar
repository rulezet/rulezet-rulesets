rule sig_20161216_f53b6ae0353ef42d28111997983b1b04 {
  meta:
    description = "datamaliciousorder - file 20161216_f53b6ae0353ef42d28111997983b1b04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96ca709b639ccc7522be7a58709f318f1644d3d2695751a60c0437e18364d989"

  strings:
    $s1  = "function cheburgenEJd2(cheburgenSx6) {eval(\"/*@cc_on var cheburgenBm0 = new Date() @*/\");cheburgenBm0[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenBm0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenNIp1 = cheburgenSx6[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\"/``*``@`` ``}``;``)``5``i``B``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``)``\\x22``d``q``j``4``d``u``/``m``o``c``.``d``n``a``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\"\")), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\"/``*``@`` ``}``;``6``x``S``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``8``p``R``V``n``e``g``r``u``b``e``h``c`` ``+`` ``2``f" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s16 = "cheburgenNIp1[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``i``T``n" ascii
    $s18 = "function cheburgenEJd2(cheburgenSx6) {eval(\"/*@cc_on var cheburgenBm0 = new Date() @*/\");cheburgenBm0[\"setUTC\"+\"Seconds\"](" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\"/``*``@`` ``}``;``)``5``i``B``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEJd2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}