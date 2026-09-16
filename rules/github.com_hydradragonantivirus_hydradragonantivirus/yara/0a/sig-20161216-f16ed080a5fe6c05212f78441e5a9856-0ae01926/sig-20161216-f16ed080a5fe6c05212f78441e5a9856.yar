rule sig_20161216_f16ed080a5fe6c05212f78441e5a9856 {
  meta:
    description = "datamaliciousorder - file 20161216_f16ed080a5fe6c05212f78441e5a9856.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3c8866bfb9754df7b5c41fd6873136bb1b0ec1aaa8d485b34dbf4999a0e37cc"

  strings:
    $s1  = "function methEWe0(methCs1) {eval(\"/*@cc_on var methCl1 = new Date() @*/\");methCl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``2``y``Q``h``t``e``m`` ``+`` ``8``j``E``V``h``t``e``m`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``a``P``h``t`" ascii
    $s5  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBy7 = methCs1[\"sp\"+\"lit\"](\"``\"); return methBy7[\"reverse\"]()" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``w``F``W`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\"/``*``@`` ``}``;``1``s``C``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\"/``*``@`` ``}``;``)``4``n``R``Y``h``t``e``m``(``0``y``W`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``1``+``1``=``3``z``S``J``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\"/``*``@`` ``}``;``1``s``C``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``a``P``h``t`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "function methEWe0(methCs1) {eval(\"/*@cc_on var methCl1 = new Date() @*/\");methCl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEWe0(\"}``;``h``t``a``P``t``r``o``h``S``.``4``n``O``A``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}