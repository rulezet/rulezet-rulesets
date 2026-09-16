rule sig_20161216_5ffe165a46f2fdb81a0f4fa13766a8e2 {
  meta:
    description = "datamaliciousorder - file 20161216_5ffe165a46f2fdb81a0f4fa13766a8e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1ccf9ae1f23ec030c2412cf9635d5d6fde4f8aa4336d5b4e1e6aad717eb7cd8"

  strings:
    $s1  = "function cheburgenGBc9(cheburgenGRp9) {eval(\"/*@cc_on var cheburgenRa4 = new Date() @*/\");cheburgenRa4[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenRa4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenOx6 = cheburgenGRp9[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``1``+``1``=``9``r``S``Z``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``o``A``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\"/``*``@`` ``}``;``)``7``b``K``S``n``e``g``r``u``b``e``h" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\"/``*``@`` ``}``;``5``u``T``K``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\"}``;``h``t``a``P``t``r``o``h``S``.``5``z``I``S``n``e``g" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``y``B``X``n" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGBc9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``y``B``X``n" ascii
    $s20 = "function cheburgenGBc9(cheburgenGRp9) {eval(\"/*@cc_on var cheburgenRa4 = new Date() @*/\");cheburgenRa4[\"setUTC\"+\"Seconds\"]" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}