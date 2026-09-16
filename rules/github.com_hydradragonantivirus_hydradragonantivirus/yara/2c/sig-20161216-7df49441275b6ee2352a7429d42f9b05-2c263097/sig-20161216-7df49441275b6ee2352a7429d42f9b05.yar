rule sig_20161216_7df49441275b6ee2352a7429d42f9b05 {
  meta:
    description = "datamaliciousorder - file 20161216_7df49441275b6ee2352a7429d42f9b05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b9cd560eb911080d40a1596a6df44234546afd58e196cf196a07dabbcfb004b"

  strings:
    $s1  = "function methAx1(methPTr8) {eval(\"/*@cc_on var methIb4 = new Date() @*/\");methIb4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s4  = "function methAx1(methPTr8) {eval(\"/*@cc_on var methIb4 = new Date() @*/\");methIb4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m`" ascii
    $s7  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBy8 = methPTr8[\"sp\"+\"lit\"](\"``\"); return methBy8[\"reverse\"](" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``5``w``V``h``t``e``m`` ``+`` ``0``f``N``h``t``e``m``=``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``1``+``1``=``4``s``I``F``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\"/``*``@`` ``}``;``8``r``T``P``h``t``e``m`` ``n``r``u``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``f``M``h``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``0`` ``=`` ``1``t``F``X``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``d``V``h``t``e``m``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAx1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}