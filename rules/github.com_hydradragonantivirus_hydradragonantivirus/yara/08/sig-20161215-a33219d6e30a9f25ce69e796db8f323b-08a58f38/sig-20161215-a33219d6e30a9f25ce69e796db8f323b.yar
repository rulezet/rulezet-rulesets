rule sig_20161215_a33219d6e30a9f25ce69e796db8f323b {
  meta:
    description = "datamaliciousorder - file 20161215_a33219d6e30a9f25ce69e796db8f323b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9024898072ec264e02f0ef85eebe1d92151514aa5ebace33006afadce1bf6e6f"

  strings:
    $s1  = "function cheburgenDWx1(cheburgenJz5) {eval(\"/*@cc_on var cheburgenIt0 = new Date() @*/\");cheburgenIt0[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenIt0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenSKk1 = cheburgenJz5[\"split\"](\"``" ascii
    $s3  = "cheburgenSKk1[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``c``F``R" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\"/``*``@`` ``}``;``1``k``K``S``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\"/``*``@`` ``}``;``1``k``K``S``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``i``C``W``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\"/``*``@`` ``}``;``)``6``t``D``M``n``e``g``r``u``b``e``h" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``0`` ``=`` ``1``e``N``X``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\"/``*``@`` ``}``;``5``i``S``Q``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\"/``*``@`` ``}``;``5``i``S``Q``n``e``g``r``u``b``e``h``c" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``)``\\x22``\\x22`` ``+`` ``3``g``G``n``e``g``r``u``b`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\"\")), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDWx1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}