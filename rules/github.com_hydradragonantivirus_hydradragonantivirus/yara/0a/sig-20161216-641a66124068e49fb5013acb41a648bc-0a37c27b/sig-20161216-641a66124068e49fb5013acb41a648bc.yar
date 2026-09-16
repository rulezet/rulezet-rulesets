rule sig_20161216_641a66124068e49fb5013acb41a648bc {
  meta:
    description = "datamaliciousorder - file 20161216_641a66124068e49fb5013acb41a648bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdfa40b06ed8048decb1db5a5d8c7ac04ad79fabb9f09bbdb5a6af3b401e1250"

  strings:
    $s1  = "0\");if (cheburgenQy3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenXEe8 = cheburgenLb5[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenQe7(cheburgenLb5) {eval(\"/*@cc_on var cheburgenQy3 = new Date() @*/\");cheburgenQy3[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``m``G``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``e" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``1``+``1``=``7``u``J``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``8``c``F``H``n``e``g``r``u``b``e``h``c`` ``+`` ``3``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``a" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``)``\\x22``\\x22`` ``+`` ``9``s``C``n``e``g``r``u``b``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``8``c``F``H``n``e``g``r``u``b``e``h``c`` ``+`` ``3``e`" ascii
    $s12 = "function cheburgenQe7(cheburgenLb5) {eval(\"/*@cc_on var cheburgenQy3 = new Date() @*/\");cheburgenQy3[\"setUTC\"+\"Seconds\"](" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\"/``*``@`` ``}``;``8``e``E``X``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\"/``*``@`` ``}``;``2``s``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\"/``*``@`` ``}``;``5``b``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``0`` ``=`` ``0``q``J``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQe7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}