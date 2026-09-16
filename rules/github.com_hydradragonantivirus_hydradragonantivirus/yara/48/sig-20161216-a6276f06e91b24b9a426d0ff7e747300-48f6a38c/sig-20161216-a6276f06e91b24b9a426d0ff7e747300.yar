rule sig_20161216_a6276f06e91b24b9a426d0ff7e747300 {
  meta:
    description = "datamaliciousorder - file 20161216_a6276f06e91b24b9a426d0ff7e747300.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80ccedbfb7385dd592e8cd33e3223447d78de0e7069a2870ff484e1a66d07ae1"

  strings:
    $s1  = "function cheburgenYAy2(cheburgenTh8) {eval(\"/*@cc_on var cheburgenTn1 = new Date() @*/\");cheburgenTn1[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenTn1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenQw6 = cheburgenTh8[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``)``\\x22``g``k``q``0``4``n``w``3``/``u``r``.``o``n``" ascii
    $s4  = "function cheburgenYAy2(cheburgenTh8) {eval(\"/*@cc_on var cheburgenTn1 = new Date() @*/\");cheburgenTn1[\"setUTC\"+\"Seconds\"](" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\"/``*``@`` ``}``;``8``h``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``1``+``1``=``5``g``A``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\"/``*``@`` ``}``;``8``h``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\"/``*``@`` ``}``;``3``r``E``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``k``Q``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``)``\\x22``\\x22`` ``+`` ``6``b``I``I``n``e``g``r``u`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``p``E``H``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\"/``*``@`` ``}``;``3``r``E``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``2``i``K``n``e``g``r``u``b``e``h``c`` ``+`` ``3``e``C" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``)``\\x22``\\x22`` ``+`` ``6``b``I``I``n``e``g``r``u`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYAy2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}