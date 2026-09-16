rule sig_20161216_d6efead357c6e1bf3a16d9a908f75f8d {
  meta:
    description = "datamaliciousorder - file 20161216_d6efead357c6e1bf3a16d9a908f75f8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01d630bb026d6882aaddea2329bf7e106cc55f687d1c6ccee956b621b5cc64ab"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMOa7 = methMo9[\"sp\"+\"lit\"](\"``\"); return methMOa7[\"reverse" ascii
    $s2  = "function methIj8(methMo9) {eval(\"/*@cc_on var methKLb8 = new Date() @*/\");methKLb8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``d``M``I``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\"/``*``@`` ``}``;``9``w``T``S``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\"/``*``@`` ``}``;``9``o``M``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\"/``*``@`` ``}``;``)``6``w``M``h``t``e``m``(``4``t``L``h``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``1``+``1``=``5``p``K``I``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\"}``;``h``t``a``P``t``r``o``h``S``.``9``f``Z``H``h``t``e``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIj8(\";``0`` ``=`` ``8``l``W``h``t``e``m`` ``r``a``v\"))), 1);/" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}