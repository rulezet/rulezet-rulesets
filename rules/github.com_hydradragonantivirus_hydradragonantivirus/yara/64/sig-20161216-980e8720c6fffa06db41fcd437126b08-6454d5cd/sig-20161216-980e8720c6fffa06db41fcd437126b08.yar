rule sig_20161216_980e8720c6fffa06db41fcd437126b08 {
  meta:
    description = "datamaliciousorder - file 20161216_980e8720c6fffa06db41fcd437126b08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9d6d994eb816dcef2f08884121f3032c9ed66322c6c448ac36d3ad6a0e9c89c"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methISo7 = methFw7[\"sp\"+\"lit\"](\"``\"); return methISo7[\"revers" ascii
    $s2  = "function methHAe2(methFw7) {eval(\"/*@cc_on var methAWg5 = new Date() @*/\");methAWg5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\"/``*``@`` ``}``;``7``o``S``I``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``0`` ``=`` ``9``u``Z``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\"/``*``@`` ``}``;``7``w``F``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``s``M``I``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``g``Z``U`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``0`` ``=`` ``9``u``Z``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\"/``*``@`` ``}``;``0``k``V``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHAe2(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}