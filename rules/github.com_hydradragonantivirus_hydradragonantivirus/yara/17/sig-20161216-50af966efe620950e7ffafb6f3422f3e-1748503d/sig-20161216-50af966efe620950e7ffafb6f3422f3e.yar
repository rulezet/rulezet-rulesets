rule sig_20161216_50af966efe620950e7ffafb6f3422f3e {
  meta:
    description = "datamaliciousorder - file 20161216_50af966efe620950e7ffafb6f3422f3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33a93e0268e3435713b95d7f5db49c74c7b0295fe3e601c6e5cace3cd4d6d52d"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methNOc5 = methFh4[\"sp\"+\"lit\"](\"``\"); return methNOc5[\"reverse" ascii
    $s2  = "function methWc8(methFh4) {eval(\"/*@cc_on var methSYl1 = new Date() @*/\");methSYl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``1``+``1``=``3``f``T``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s4  = "function methWc8(methFh4) {eval(\"/*@cc_on var methSYl1 = new Date() @*/\");methSYl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\"/``*``@`` ``}``;``5``c``O``N``h``t``e``m`` ``n``r``u``t``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``k``E``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``.`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\"/``*``@`` ``}``;``4``h``F``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``0`` ``=`` ``7``v``S``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``h``A``h``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWc8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}