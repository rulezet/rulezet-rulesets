rule sig_20161216_fcac1cdf0998328beb8877517f2db784 {
  meta:
    description = "datamaliciousorder - file 20161216_fcac1cdf0998328beb8877517f2db784.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4e5854c2fd32c8bc5c4f52c5119e331c0bb3850b0a8448fd0c235f54235d236"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methYPh3 = methQy5[\"sp\"+\"lit\"](\"``\"); return methYPh3[\"reverse" ascii
    $s2  = "function methOy8(methQy5) {eval(\"/*@cc_on var methCUx2 = new Date() @*/\");methCUx2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``0`` ``=`` ``9``t``R``F``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``)``\\x22``l``k``w``x``q``n``p``w``q``/``x``m``.``m``o`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\"/``*``@`` ``}``;``)``7``c``W``h``t``e``m``(``9``a``G``h``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\"}``;``h``t``a``P``t``r``o``h``S``.``8``g``F``h``t``e``m``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\"/``*``@`` ``}``;``3``h``N``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``0`` ``=`` ``9``t``R``F``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``j``W``U``h``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOy8(\";``6``t``Q``h``t``e``m`` ``+`` ``4``c``X``W``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}