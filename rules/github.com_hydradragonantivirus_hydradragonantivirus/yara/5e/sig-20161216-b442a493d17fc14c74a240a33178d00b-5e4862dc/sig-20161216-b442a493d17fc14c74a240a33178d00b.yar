rule sig_20161216_b442a493d17fc14c74a240a33178d00b {
  meta:
    description = "datamaliciousorder - file 20161216_b442a493d17fc14c74a240a33178d00b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62ceb8300aa9d783bda018458779574cfd1c1f00ab50abbaf211c45450c131fb"

  strings:
    $s1  = "function cheburgenFYi1(cheburgenHMm4) {eval(\"/*@cc_on var cheburgenPw0 = new Date() @*/\");cheburgenPw0[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenPw0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenTq0 = cheburgenHMm4[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\"/``*``@`` ``}``;``4``m``M``H``n``e``g``r``u``b``e``h``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``)``\\x22``\\x22`` ``+`` ``0``f``Y``n``e``g``r``u``b`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\"/``*``@`` ``}``;``)``4``e``Q``n``e``g``r``u``b``e``h``c" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\"/``*``@`` ``}``;``6``w``O``Y``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``0`` ``=`` ``3``c``F``B``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s12 = " cheburgenTq0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``1``+``1``=``4``p``V``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``1``+``1``=``4``p``V``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``b``J``B" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\"\")), 1);//////////////////////////////////////////////" ascii
    $s18 = "function cheburgenFYi1(cheburgenHMm4) {eval(\"/*@cc_on var cheburgenPw0 = new Date() @*/\");cheburgenPw0[\"setUTC\"+\"Seconds\"]" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFYi1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}