rule sig_20161216_3749e8ecf6d7e87d5cdcdccb8a5cc93c {
  meta:
    description = "datamaliciousorder - file 20161216_3749e8ecf6d7e87d5cdcdccb8a5cc93c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "529b8bf7b5c91d54edd44b2e828ec766b4a9d29f049f02d10d53a1c82d45bd09"

  strings:
    $s1  = "20\");if (cheburgenYy3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenKr2 = cheburgenXSq7[\"split\"](\"``" ascii
    $s2  = "function cheburgenAo2(cheburgenXSq7) {eval(\"/*@cc_on var cheburgenYy3 = new Date() @*/\");cheburgenYy3[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``." ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``0`` ``=`` ``3``x``T``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``1``+``1``=``9``o``A``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\"/``*``@`` ``}``;``2``r``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\"/``*``@`` ``}``;``)``1``r``U``W``n``e``g``r``u``b``e``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\"/``*``@`` ``}``;``2``r``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "function cheburgenAo2(cheburgenXSq7) {eval(\"/*@cc_on var cheburgenYy3 = new Date() @*/\");cheburgenYy3[\"setUTC\"+\"Seconds\"](" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\"/``*``@`` ``}``;``6``b``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\"/``*``@`` ``}``;``7``q``S``X``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\"/``*``@`` ``}``;``)``1``r``U``W``n``e``g``r``u``b``e``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``0`` ``=`` ``3``x``T``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``8``t``E``K``n``e``g``r``u``b``e``h``c`` ``+`` ``5``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAo2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}