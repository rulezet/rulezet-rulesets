rule sig_20161216_66ec3fc24b1c93ead966f7064393c132 {
  meta:
    description = "datamaliciousorder - file 20161216_66ec3fc24b1c93ead966f7064393c132.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1cb4d2b00537a7929c78d05c66b2a108b173321a7d3dff290e78494d821b35c"

  strings:
    $s1  = "\"20\");if (cheburgenHQl9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenFn5 = cheburgenCw8[\"split\"](\"`" ascii
    $s2  = "function cheburgenJh2(cheburgenCw8) {eval(\"/*@cc_on var cheburgenHQl9 = new Date() @*/\");cheburgenHQl9[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``)``\\x22``\\x22`` ``+`` ``0``u``F``P``n``e``g``r``u``" ascii
    $s4  = " cheburgenFn5[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``)``\\x22``p``a``h``5``d``d``w``b``c``5``/``m``o``c``." ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``)``\\x22``\\x22`` ``+`` ``0``u``F``P``n``e``g``r``u``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``)``\\x22``p``a``h``5``d``d``w``b``c``5``/``m``o``c``." ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\"/``*``@`` ``}``;``8``w``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "function cheburgenJh2(cheburgenCw8) {eval(\"/*@cc_on var cheburgenHQl9 = new Date() @*/\");cheburgenHQl9[\"setUTC\"+\"Seconds\"]" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\"/``*``@`` ``}``;``)``0``w``P``X``n``e``g``r``u``b``e``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``1``+``1``=``5``v``I``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``z``X``O``n`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``)``\\x22``n``p``u``a``b``u``/``g``r``o``.``e``v``i``t" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\"/``*``@`` ``}``;``)``0``w``P``X``n``e``g``r``u``b``e``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJh2(\";``6``f``C``U``n``e``g``r``u``b``e``h``c`` ``+`` ``6``y`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}