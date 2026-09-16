rule sig_20161216_8f328f5b8a2613b62ed7cd628bf91a54 {
  meta:
    description = "datamaliciousorder - file 20161216_8f328f5b8a2613b62ed7cd628bf91a54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1af1a5a97c66c44034314834314fe2eb764d0d68483120288ccc95716f17f9b"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCZt2 = methZOv7[\"sp\"+\"lit\"](\"``\"); return methCZt2[\"reve" ascii
    $s2  = "function methGAg4(methZOv7) {eval(\"/*@cc_on var methTNa0 = new Date() @*/\");methTNa0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "function methGAg4(methZOv7) {eval(\"/*@cc_on var methTNa0 = new Date() @*/\");methTNa0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``)``\\x22``v``j``g``l``2``z``/``m``o``c``.``t``i``s``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``e``B``T``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\"/``*``@`` ``}``;``3``l``H``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\"/``*``@`` ``}``;``3``l``H``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``0`` ``=`` ``4``i``P``W``h``t``e``m`` ``r``a``v\"))), " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``8``d``S``h``t``e``m`` ``+`` ``3``a``J``J``h``t``e``m`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\"/``*``@`` ``}``;``2``t``Z``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``8``d``S``h``t``e``m`` ``+`` ``3``a``J``J``h``t``e``m`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGAg4(\";``1``+``1``=``9``m``D``B``h``t``e``m`` ``r``a``v``;``)`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}