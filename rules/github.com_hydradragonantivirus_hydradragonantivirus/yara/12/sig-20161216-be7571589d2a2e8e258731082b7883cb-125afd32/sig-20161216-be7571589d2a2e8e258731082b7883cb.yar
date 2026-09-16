rule sig_20161216_be7571589d2a2e8e258731082b7883cb {
  meta:
    description = "datamaliciousorder - file 20161216_be7571589d2a2e8e258731082b7883cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11427b10e7e5646057b3833289a8cc473b7a5d99c6be52e2426c00da8f3c4a9d"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methWj8 = methAq0[\"sp\"+\"lit\"](\"``\"); return methWj8[\"reverse" ascii
    $s2  = "function methQCd4(methAq0) {eval(\"/*@cc_on var methDZx1 = new Date() @*/\");methDZx1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``0`` ``=`` ``7``b``M``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``1``+``1``=``8``z``T``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``j``F``L`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\"/``*``@`` ``}``;``)``1``b``F``h``t``e``m``(``3``w``C``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``j``F``L`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\"/``*``@`` ``}``;``0``q``A``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\"/``*``@`` ``}``;``5``v``K``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCd4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}