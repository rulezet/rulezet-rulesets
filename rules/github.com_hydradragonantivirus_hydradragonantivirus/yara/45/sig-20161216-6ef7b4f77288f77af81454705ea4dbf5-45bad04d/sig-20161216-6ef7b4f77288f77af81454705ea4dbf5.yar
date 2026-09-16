rule sig_20161216_6ef7b4f77288f77af81454705ea4dbf5 {
  meta:
    description = "datamaliciousorder - file 20161216_6ef7b4f77288f77af81454705ea4dbf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a7fc9ff0135a0a3ce76b3a9cd87728b371e8d903f11924afe30032c50226bb6"

  strings:
    $s1  = "function methDVk8(methLd7) {eval(\"/*@cc_on var methOWp8 = new Date() @*/\");methOWp8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methRv8 = methLd7[\"sp\"+\"lit\"](\"``\"); return methRv8[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\"/``*``@`` ``}``;``9``u``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "function methDVk8(methLd7) {eval(\"/*@cc_on var methOWp8 = new Date() @*/\");methOWp8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``x``R``H`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\"/``*``@`` ``}``;``9``u``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\"/``*``@`` ``}``;``)``2``e``W``h``t``e``m``(``8``l``K``R`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\"/``*``@`` ``}``;``8``v``R``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``a``U``h``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDVk8(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}