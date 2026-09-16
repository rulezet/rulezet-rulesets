rule sig_20161215_cdf6c07997c956e5ac5d3c9e4b921426 {
  meta:
    description = "datamaliciousorder - file 20161215_cdf6c07997c956e5ac5d3c9e4b921426.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f17a1a5fcfd0f1f6be4b73567c91be15db60a42391d15ec381df7f06d8ce0b01"

  strings:
    $s1  = "20\");if (cheburgenNu3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenUu2 = cheburgenNt1[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenSDi6(cheburgenNt1) {eval(\"/*@cc_on var cheburgenNu3 = new Date() @*/\");cheburgenNu3[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``a``C``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\"/``*``@`` ``}``;``)``0``v``N``P``n``e``g``r``u``b``e``h" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\"/``*``@`` ``}``;``9``a``G``G``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``)``\\x22``h``h``3``m``u``5``e``z``t``/``m``o``c``.``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``)``\\x22``p``a``h``5``d``d``w``b``c``5``/``m``o``c``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s11 = "function cheburgenSDi6(cheburgenNt1) {eval(\"/*@cc_on var cheburgenNu3 = new Date() @*/\");cheburgenNu3[\"setUTC\"+\"Seconds\"](" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``f``G``L``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``1``+``1``=``0``z``E``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``0`` ``=`` ``3``f``R``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\"/``*``@`` ``}``;``1``t``N``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``5``k``N``n``e``g``r``u``b``e``h``c`` ``+`` ``5``q``S" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\";``)``\\x22``n``p``u``a``b``u``/``g``r``o``.``e``v``i``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSDi6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}