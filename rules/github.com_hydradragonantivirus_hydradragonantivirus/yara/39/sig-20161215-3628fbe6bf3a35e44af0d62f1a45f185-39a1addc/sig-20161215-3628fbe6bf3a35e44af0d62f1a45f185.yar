rule sig_20161215_3628fbe6bf3a35e44af0d62f1a45f185 {
  meta:
    description = "datamaliciousorder - file 20161215_3628fbe6bf3a35e44af0d62f1a45f185.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "788f1793da9b05ad6f1bd523ce3958d8ca68338ceb52f3bb946deae58c6769ea"

  strings:
    $s1  = "0\");if (cheburgenRh1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenTc4 = cheburgenTn7[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenKh9(cheburgenTn7) {eval(\"/*@cc_on var cheburgenRh1 = new Date() @*/\");cheburgenRh1[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``1``+``1``=``4``r``W``Q``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``1``l``Q``n``e``g``r``u``b``e``h``c`` ``+`` ``5``o``V`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``x``S``n`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``1``l``Q``n``e``g``r``u``b``e``h``c`` ``+`` ``5``o``V`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "function cheburgenKh9(cheburgenTn7) {eval(\"/*@cc_on var cheburgenRh1 = new Date() @*/\");cheburgenRh1[\"setUTC\"+\"Seconds\"](" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\"/``*``@`` ``}``;``5``o``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\"/``*``@`` ``}``;``7``n``T``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``s``V``Z``n`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\"/``*``@`` ``}``;``)``9``e``Y``D``n``e``g``r``u``b``e``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKh9(\"/``*``@`` ``}``;``5``o``V``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}