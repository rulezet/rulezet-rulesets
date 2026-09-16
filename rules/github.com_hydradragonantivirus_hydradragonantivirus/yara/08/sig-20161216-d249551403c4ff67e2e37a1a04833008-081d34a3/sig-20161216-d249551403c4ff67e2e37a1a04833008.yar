rule sig_20161216_d249551403c4ff67e2e37a1a04833008 {
  meta:
    description = "datamaliciousorder - file 20161216_d249551403c4ff67e2e37a1a04833008.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "259ebb72f6b7a14174e475984a227af04f15dd89a288ad972e3d1793248daadd"

  strings:
    $s1  = "\"20\");if (cheburgenNIh6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenOh5 = cheburgenUg7[\"split\"](\"`" ascii
    $s2  = "function cheburgenVf2(cheburgenUg7) {eval(\"/*@cc_on var cheburgenNIh6 = new Date() @*/\");cheburgenNIh6[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``)``\\x22``\\x22`` ``+`` ``5``q``O``n``e``g``r``u``b``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``v``Q``n`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\"/``*``@`` ``}``;``)``9``a``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``0`` ``=`` ``9``d``D``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\"/``*``@`` ``}``;``)``9``a``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``1``+``1``=``2``u``B``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``-" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``a" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\"/``*``@`` ``}``;``7``g``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``k``R``F``n`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``)``\\x22``d``q``j``4``d``u``/``m``o``c``.``d``n``a``l" ascii
    $s16 = " cheburgenOh5[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``k``R``F``n`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``1``+``1``=``2``u``B``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVf2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}