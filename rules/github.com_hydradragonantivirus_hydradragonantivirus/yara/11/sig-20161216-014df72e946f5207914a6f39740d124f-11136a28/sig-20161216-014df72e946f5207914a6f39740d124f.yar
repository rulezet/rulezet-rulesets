rule sig_20161216_014df72e946f5207914a6f39740d124f {
  meta:
    description = "datamaliciousorder - file 20161216_014df72e946f5207914a6f39740d124f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "306a6bbcd31d53fc84f345889f71b9f78e0fe8ea597a4afe0a10080bf6e61d8c"

  strings:
    $s1  = "0\");if (cheburgenFy7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenBk3 = cheburgenUy6[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenAo7(cheburgenUy6) {eval(\"/*@cc_on var cheburgenFy7 = new Date() @*/\");cheburgenFy7[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\"/``*``@`` ``}``;``3``d``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``b``T``I``n`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``)``\\x22``\\x22`` ``+`` ``4``u``P``Q``n``e``g``r``u``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\"/``*``@`` ``}``;``3``d``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``)``\\x22``\\x22`` ``+`` ``4``u``P``Q``n``e``g``r``u``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``q``C``I`" ascii
    $s15 = "eburgenBk3[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\"/``*``@`` ``}``;``)``5``a``J``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``s" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo7(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}