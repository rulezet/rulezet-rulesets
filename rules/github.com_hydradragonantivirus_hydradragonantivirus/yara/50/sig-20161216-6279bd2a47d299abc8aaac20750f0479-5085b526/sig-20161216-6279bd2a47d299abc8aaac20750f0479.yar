rule sig_20161216_6279bd2a47d299abc8aaac20750f0479 {
  meta:
    description = "datamaliciousorder - file 20161216_6279bd2a47d299abc8aaac20750f0479.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5771d6b23b5deb4abb945a3ec99611abe1b8546f5682060f7215727d898bd5c7"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methRy3 = methLr0[\"sp\"+\"lit\"](\"``\"); return methRy3[\"reverse" ascii
    $s2  = "function methGWc8(methLr0) {eval(\"/*@cc_on var methHNs5 = new Date() @*/\");methHNs5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\"/``*``@`` ``}``;``8``k``B``E``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\"}``;``h``t``a``P``t``r``o``h``S``.``3``p``R``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\"}``;``h``t``a``P``t``r``o``h``S``.``3``p``R``h``t``e``m`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\"/``*``@`` ``}``;``0``r``L``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``3``n``E``h``t``e``m`` ``+`` ``9``d``J``h``t``e``m``=`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``1``+``1``=``6``a``L``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\"/``*``@`` ``}``;``)``7``e``V``h``t``e``m``(``4``k``R``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``u``I``h``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGWc8(\"/``*``@`` ``}``;``8``k``B``E``h``t``e``m`` ``n``r``u``t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}