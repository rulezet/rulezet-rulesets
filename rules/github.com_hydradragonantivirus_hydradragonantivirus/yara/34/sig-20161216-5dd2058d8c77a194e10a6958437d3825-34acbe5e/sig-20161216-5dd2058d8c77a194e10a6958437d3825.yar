rule sig_20161216_5dd2058d8c77a194e10a6958437d3825 {
  meta:
    description = "datamaliciousorder - file 20161216_5dd2058d8c77a194e10a6958437d3825.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37d67c53f50e033a4ddf23cbcff277a6e080736ab773a232b5612efa59c36454"

  strings:
    $s1  = "function methYq8(methEHn9) {eval(\"/*@cc_on var methKZn8 = new Date() @*/\");methKZn8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCe0 = methEHn9[\"sp\"+\"lit\"](\"``\"); return methCe0[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\"/``*``@`` ``}``;``0``e``C``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s5  = "function methYq8(methEHn9) {eval(\"/*@cc_on var methKZn8 = new Date() @*/\");methKZn8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``l``M``A``h``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``1``+``1``=``3``c``T``B``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``3``g``J``h``t``e``m`` ``+`` ``6``n``F``I``h``t``e``m``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\"/``*``@`` ``}``;``5``m``U``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\"/``*``@`` ``}``;``0``e``C``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\"}``;``h``t``a``P``t``r``o``h``S``.``8``j``G``V``h``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\"/``*``@`` ``}``;``9``n``H``E``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYq8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``e``Y``h``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}