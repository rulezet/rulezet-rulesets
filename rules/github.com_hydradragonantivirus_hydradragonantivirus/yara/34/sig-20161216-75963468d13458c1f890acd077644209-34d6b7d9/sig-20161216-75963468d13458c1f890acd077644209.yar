rule sig_20161216_75963468d13458c1f890acd077644209 {
  meta:
    description = "datamaliciousorder - file 20161216_75963468d13458c1f890acd077644209.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87ee13fce22433c8bab90dd9494489b655136ea5ee7e4011d99029eb0f969ea7"

  strings:
    $s1  = "function cheburgenASx8(cheburgenYe9) {eval(\"/*@cc_on var cheburgenWq7 = new Date() @*/\");cheburgenWq7[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenWq7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenHi8 = cheburgenYe9[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``)``\\x22``m``e``k``k``8``u``o``/``m``o``c``.``s``n``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"/``*``@`` ``}``;``5``m``H``K``n``e``g``r``u``b``e``h``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"/``*``@`` ``}``;``8``i``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``e``T``K``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"\")), 1);//////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"\")), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"/``*``@`` ``}``;``9``e``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"/``*``@`` ``}``;``9``e``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``5``z``W``n``e``g``r``u``b``e``h``c`` ``+`` ``7``i``S" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\"/``*``@`` ``}``;``)``3``d``K``D``n``e``g``r``u``b``e``h" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASx8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}