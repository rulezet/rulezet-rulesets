rule sig_20161216_6ee8e92c36d43a84f4f4d75fca5f97dd {
  meta:
    description = "datamaliciousorder - file 20161216_6ee8e92c36d43a84f4f4d75fca5f97dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae91ffdcff6c039031b87f5207030e3cc775ccd94df970234f30765c0c6f4512"

  strings:
    $s1  = "function methNMw0(methRJi1) {eval(\"/*@cc_on var methYu1 = new Date() @*/\");methYu1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\"/``*``@`` ``}``;``1``i``J``R``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``1``z``E``h``t``e``m`` ``+`` ``5``a``S``C``h``t``e``m`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``1``z``E``h``t``e``m`` ``+`` ``5``a``S``C``h``t``e``m`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\"/``*``@`` ``}``;``8``f``C``M``h``t``e``m`` ``n``r``u``t`" ascii
    $s14 = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMCf8 = methRJi1[\"sp\"+\"lit\"](\"``\"); return methMCf8[\"reverse" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\"/``*``@`` ``}``;``8``f``C``M``h``t``e``m`` ``n``r``u``t`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``h``J``h``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\"/``*``@`` ``}``;``)``9``d``G``h``t``e``m``(``7``b``P``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMw0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "function methNMw0(methRJi1) {eval(\"/*@cc_on var methYu1 = new Date() @*/\");methYu1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}