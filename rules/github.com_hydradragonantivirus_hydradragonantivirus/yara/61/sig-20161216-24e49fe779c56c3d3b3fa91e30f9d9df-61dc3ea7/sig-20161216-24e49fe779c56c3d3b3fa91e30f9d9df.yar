rule sig_20161216_24e49fe779c56c3d3b3fa91e30f9d9df {
  meta:
    description = "datamaliciousorder - file 20161216_24e49fe779c56c3d3b3fa91e30f9d9df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d95a39872bbac305d2e5ad940912bd38e262ed4b6fe41508a97d504ee714ef9b"

  strings:
    $s1  = "function methPz1(methRj0) {eval(\"/*@cc_on var methPo2 = new Date() @*/\");methPo2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methPz1(methRj0) {eval(\"/*@cc_on var methPo2 = new Date() @*/\");methPo2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\"/``*``@`` ``}``;``3``q``D``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``5``x``K``U``h``t``e``m`` ``+`` ``3``g``O``h``t``e``m``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``1``+``1``=``5``w``F``B``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\"/``*``@`` ``}``;``4``q``A``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methIAq4 = methRj0[\"sp\"+\"lit\"](\"``\"); return methIAq4[\"reverse\"](" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``n``W``R``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\"}``;``h``t``a``P``t``r``o``h``S``.``3``v``V``K``h``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\"/``*``@`` ``}``;``0``j``R``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\";``0`` ``=`` ``8``i``H``P``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPz1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}