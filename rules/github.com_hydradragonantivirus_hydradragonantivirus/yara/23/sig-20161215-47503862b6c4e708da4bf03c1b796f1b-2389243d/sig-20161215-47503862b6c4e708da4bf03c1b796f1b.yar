rule sig_20161215_47503862b6c4e708da4bf03c1b796f1b {
  meta:
    description = "datamaliciousorder - file 20161215_47503862b6c4e708da4bf03c1b796f1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e067f2d69b342cbcf1c5d4bb9afe1cd7cb86b017365345fc56b2b74804253f8"

  strings:
    $s1  = "0\");if (cheburgenUa4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenDe9 = cheburgenIo1[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenIl4(cheburgenIo1) {eval(\"/*@cc_on var cheburgenUa4 = new Date() @*/\");cheburgenUa4[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``k" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``d" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\"/``*``@`` ``}``;``9``p``U``T``n``e``g``r``u``b``e``h``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\"}``;``h``t``a``P``t``r``o``h``S``.``4``p``Q``W``n``e``g`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "eburgenDe9[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``0`` ``=`` ``5``y``F``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\"/``*``@`` ``}``;``9``p``U``T``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\"}``;``h``t``a``P``t``r``o``h``S``.``4``p``Q``W``n``e``g`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\"/``*``@`` ``}``;``)``7``m``X``F``n``e``g``r``u``b``e``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``h``E``n``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIl4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}