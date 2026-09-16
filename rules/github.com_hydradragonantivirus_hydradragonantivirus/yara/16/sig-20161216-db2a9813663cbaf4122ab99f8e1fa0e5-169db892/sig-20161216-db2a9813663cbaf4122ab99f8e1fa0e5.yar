rule sig_20161216_db2a9813663cbaf4122ab99f8e1fa0e5 {
  meta:
    description = "datamaliciousorder - file 20161216_db2a9813663cbaf4122ab99f8e1fa0e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ada68dfaab89b6117c5656b5c3de72228cfd5b3beeee7c4033a29c97d4765c80"

  strings:
    $s1  = "function methQs5(methRKs5) {eval(\"/*@cc_on var methDYx5 = new Date() @*/\");methDYx5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methRd5 = methRKs5[\"sp\"+\"lit\"](\"``\"); return methRd5[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s5  = "function methQs5(methRKs5) {eval(\"/*@cc_on var methDYx5 = new Date() @*/\");methDYx5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``v``F``Z``h``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``0`` ``=`` ``1``z``Y``L``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\"/``*``@`` ``}``;``5``d``R``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\"/``*``@`` ``}``;``8``w``G``Z``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\"/``*``@`` ``}``;``5``s``K``R``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQs5(\"/``*``@`` ``}``;``8``w``G``Z``h``t``e``m`` ``n``r``u``t``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}