rule sig_20161216_7ee3b5c2573dc3ae565af761b1408b87 {
  meta:
    description = "datamaliciousorder - file 20161216_7ee3b5c2573dc3ae565af761b1408b87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db321bfe7e06668c133992eb4ce1d723d5fbf8a02c94cabce672fe7d85f6aba1"

  strings:
    $s1  = "function methGMz9(methRr5) {eval(\"/*@cc_on var methPEd5 = new Date() @*/\");methPEd5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methFNp2 = methRr5[\"sp\"+\"lit\"](\"``\"); return methFNp2[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\"/``*``@`` ``}``;``2``p``N``F``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``)``\\x22``4``m``e``j``f``/``a``b``.``m``o``c``.``n``o" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``1``+``1``=``7``c``N``W``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\"/``*``@`` ``}``;``1``w``X``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\"/``*``@`` ``}``;``5``r``R``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\"}``;``h``t``a``P``t``r``o``h``S``.``3``k``J``h``t``e``m`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGMz9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``l``W``H``h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}