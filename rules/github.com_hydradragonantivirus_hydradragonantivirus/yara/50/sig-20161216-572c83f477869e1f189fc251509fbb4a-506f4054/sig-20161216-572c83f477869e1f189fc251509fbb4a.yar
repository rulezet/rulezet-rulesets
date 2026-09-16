rule sig_20161216_572c83f477869e1f189fc251509fbb4a {
  meta:
    description = "datamaliciousorder - file 20161216_572c83f477869e1f189fc251509fbb4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4748cfaf7e57bc8c3948e1b90c9729b729baf1c6f852e655874519978ae37597"

  strings:
    $s1  = "function methDOq8(methWg1) {eval(\"/*@cc_on var methXZp2 = new Date() @*/\");methXZp2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMSz7 = methWg1[\"sp\"+\"lit\"](\"``\"); return methMSz7[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\"/``*``@`` ``}``;``9``l``F``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``c``R``I``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\"/``*``@`` ``}``;``)``6``e``M``h``t``e``m``(``0``x``T``W`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\"/``*``@`` ``}``;``)``6``e``M``h``t``e``m``(``0``x``T``W`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDOq8(\";``0`` ``=`` ``5``e``C``F``h``t``e``m`` ``r``a``v\"))), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}