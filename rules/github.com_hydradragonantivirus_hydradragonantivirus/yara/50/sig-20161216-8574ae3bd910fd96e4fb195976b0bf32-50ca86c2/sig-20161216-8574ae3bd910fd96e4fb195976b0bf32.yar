rule sig_20161216_8574ae3bd910fd96e4fb195976b0bf32 {
  meta:
    description = "datamaliciousorder - file 20161216_8574ae3bd910fd96e4fb195976b0bf32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4e02b285e079e9b1a32ac70918a1f933566ac63a5613865b1e57f3722adda93"

  strings:
    $s1  = "function cheburgenBp9(cheburgenVKt7) {eval(\"/*@cc_on var cheburgenJl1 = new Date() @*/\");cheburgenJl1[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenJl1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenVHx1 = cheburgenVKt7[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``2``g``J``H``n``e``g``r``u``b``e``h``c`` ``+`` ``8``v`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``m``D``n``e``g``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\"/``*``@`` ``}``;``7``t``K``V``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "function cheburgenBp9(cheburgenVKt7) {eval(\"/*@cc_on var cheburgenJl1 = new Date() @*/\");cheburgenJl1[\"setUTC\"+\"Seconds\"](" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``-" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``0`` ``=`` ``1``e``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\"/``*``@`` ``}``;``8``y``V``U``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\"/``*``@`` ``}``;``8``y``V``U``n``e``g``r``u``b``e``h``c`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\"/``*``@`` ``}``;``1``x``H``V``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``)``\\x22``\\x22`` ``+`` ``1``k``Z``P``n``e``g``r``u``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBp9(\";``)``\\x22``d``q``j``4``d``u``/``m``o``c``.``d``n``a``l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}