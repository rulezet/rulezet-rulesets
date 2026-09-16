rule sig_20161216_92ec36bf674ffd544ac7af0f3be182b0 {
  meta:
    description = "datamaliciousorder - file 20161216_92ec36bf674ffd544ac7af0f3be182b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3c2ce1cf2928bad8bf0304184fd12ba22311275bdbe9234bb914eac118d5db5"

  strings:
    $s1  = "function methBu2(methBNb0) {eval(\"/*@cc_on var methZb9 = new Date() @*/\");methZb9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s3  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methSMk2 = methBNb0[\"sp\"+\"lit\"](\"``\"); return methSMk2[\"reverse\"" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``)``\\x22``g``j``g``i``0``/``m``o``c``.``g``n``o``s``n`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\"/``*``@`` ``}``;``2``k``M``S``h``t``e``m`` ``n``r``u``t``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``0`` ``=`` ``9``k``J``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\"/``*``@`` ``}``;``)``2``i``O``F``h``t``e``m``(``3``i``Z``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\"}``;``h``t``a``P``t``r``o``h``S``.``9``d``T``W``h``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``)``\\x22``4``m``e``j``f``/``a``b``.``m``o``c``.``n``o`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``x``S``h``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\";``1``+``1``=``5``p``D``L``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBu2(\"}``;``h``t``a``P``t``r``o``h``S``.``9``d``T``W``h``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}