rule sig_20161216_7dfe91f4e8206a4dbb4be6e3793f8a31 {
  meta:
    description = "datamaliciousorder - file 20161216_7dfe91f4e8206a4dbb4be6e3793f8a31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c61ef4ebd7ca67138d5a173cf5d7d9d0fefb4f3ab6e9ab795dc4bf1acc23542f"

  strings:
    $s1  = "function methHNm1(methEe8) {eval(\"/*@cc_on var methSXo2 = new Date() @*/\");methSXo2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methLp6 = methEe8[\"sp\"+\"lit\"](\"``\"); return methLp6[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\"}``;``h``t``a``P``t``r``o``h``S``.``7``q``G``M``h``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\"}``;``h``t``a``P``t``r``o``h``S``.``7``q``G``M``h``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``0`` ``=`` ``6``n``M``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``t``T``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``t``T``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\"/``*``@`` ``}``;``7``s``U``F``h``t``e``m`` ``n``r``u``t`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\"/``*``@`` ``}``;``8``e``E``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``f``K``C``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHNm1(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}