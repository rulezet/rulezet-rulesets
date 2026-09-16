rule sig_20161216_600cda70b5ea4710892d035728ad42fe {
  meta:
    description = "datamaliciousorder - file 20161216_600cda70b5ea4710892d035728ad42fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe2936d0e84fc1002e46ceeece453b33b7c4a61781e6abe4bac6aaa7ca8384de"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methNp3 = methXy9[\"sp\"+\"lit\"](\"``\"); return methNp3[\"reverse\"]" ascii
    $s2  = "function methUm9(methXy9) {eval(\"/*@cc_on var methBLe0 = new Date() @*/\");methBLe0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\"/``*``@`` ``}``;``3``p``N``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``k``T``h``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\"/``*``@`` ``}``;``)``8``q``G``h``t``e``m``(``5``k``E``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``2``t``P``E``h``t``e``m`` ``+`` ``0``k``A``h``t``e``m``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\"/``*``@`` ``}``;``9``y``X``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``.`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\"/``*``@`` ``}``;``)``8``q``G``h``t``e``m``(``5``k``E``h``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``1``+``1``=``7``d``Q``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\"/``*``@`` ``}``;``0``z``U``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s19 = "function methUm9(methXy9) {eval(\"/*@cc_on var methBLe0 = new Date() @*/\");methBLe0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}