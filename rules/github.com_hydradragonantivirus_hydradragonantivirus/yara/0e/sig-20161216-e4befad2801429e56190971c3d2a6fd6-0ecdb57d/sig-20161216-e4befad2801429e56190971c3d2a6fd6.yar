rule sig_20161216_e4befad2801429e56190971c3d2a6fd6 {
  meta:
    description = "datamaliciousorder - file 20161216_e4befad2801429e56190971c3d2a6fd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "268f36b77f6711b13fa7a24fbf1ebcb535abe3abdcd8aaf453785b01f75e7f96"

  strings:
    $s1  = "function methGh5(methFy4) {eval(\"/*@cc_on var methMOt2 = new Date() @*/\");methMOt2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methOBl9 = methFy4[\"sp\"+\"lit\"](\"``\"); return methOBl9[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``z``D``V``h``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``1``+``1``=``2``b``S``G``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``0`` ``=`` ``0``c``U``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``)``\\x22``4``z``p``i``r``a``z``/``m``o``c``.``a``d``i`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\"/``*``@`` ``}``;``)``6``y``I``h``t``e``m``(``1``p``I``O``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``0`` ``=`` ``0``c``U``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\"}``;``h``t``a``P``t``r``o``h``S``.``2``c``H``h``t``e``m``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGh5(\"}``;``h``t``a``P``t``r``o``h``S``.``2``c``H``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}