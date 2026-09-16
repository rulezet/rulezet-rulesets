rule sig_20161216_170b278cac7a0bf9add590f994bd5bb4 {
  meta:
    description = "datamaliciousorder - file 20161216_170b278cac7a0bf9add590f994bd5bb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d6681892e98a5cd1593fd602fbef3547e77348920f19aac1721180930fc506c"

  strings:
    $s1  = "20\");if (cheburgenLn5[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenVRq7 = cheburgenMHt8[\"split\"](\"``" ascii
    $s2  = "function cheburgenDs9(cheburgenMHt8) {eval(\"/*@cc_on var cheburgenLn5 = new Date() @*/\");cheburgenLn5[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``)``\\x22``\\x22`` ``+`` ``9``t``T``n``e``g``r``u``b``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``g``S``n``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``." ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``0`` ``=`` ``8``s``E``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``1``+``1``=``5``k``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\"/``*``@`` ``}``;``8``u``I``V``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``1``u``C``Z``n``e``g``r``u``b``e``h``c`` ``+`` ``3``w`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``0`` ``=`` ``8``s``E``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s14 = "function cheburgenDs9(cheburgenMHt8) {eval(\"/*@cc_on var cheburgenLn5 = new Date() @*/\");cheburgenLn5[\"setUTC\"+\"Seconds\"](" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``." ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDs9(\";``1``+``1``=``5``k``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}