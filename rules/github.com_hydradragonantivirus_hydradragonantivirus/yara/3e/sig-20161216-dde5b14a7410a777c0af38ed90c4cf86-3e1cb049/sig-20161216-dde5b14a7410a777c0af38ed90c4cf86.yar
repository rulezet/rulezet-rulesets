rule sig_20161216_dde5b14a7410a777c0af38ed90c4cf86 {
  meta:
    description = "datamaliciousorder - file 20161216_dde5b14a7410a777c0af38ed90c4cf86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c5a346481430525a52191da09625756eaf54694b18118151ea213c2644c8a0b"

  strings:
    $s1  = "function cheburgenPh4(cheburgenJl5) {eval(\"/*@cc_on var cheburgenZw7 = new Date() @*/\");cheburgenZw7[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenZw7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenUr8 = cheburgenJl5[\"split\"](\"``\")" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``0`` ``=`` ``3``l``S``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``1``+``1``=``4``z``I``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\"/``*``@`` ``}``;``5``l``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``w``J``n`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``l" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``." ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``\\x22``\\x22`` ``+`` ``4``c``X``X``n``e``g``r``u``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``." ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\"/``*``@`` ``}``;``5``l``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\"/``*``@`` ``}``;``8``r``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPh4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}