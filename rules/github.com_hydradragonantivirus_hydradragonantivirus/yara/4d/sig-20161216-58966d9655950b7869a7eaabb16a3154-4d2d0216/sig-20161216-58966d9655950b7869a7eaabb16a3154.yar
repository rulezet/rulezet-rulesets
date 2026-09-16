rule sig_20161216_58966d9655950b7869a7eaabb16a3154 {
  meta:
    description = "datamaliciousorder - file 20161216_58966d9655950b7869a7eaabb16a3154.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d9a4f6280c1c0613374825058cf0c178c034af99e1dccd56068ab68aa8bfbf7"

  strings:
    $s1  = "function methEJv3(methCu5) {eval(\"/*@cc_on var methPu5 = new Date() @*/\");methPu5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "function methEJv3(methCu5) {eval(\"/*@cc_on var methPu5 = new Date() @*/\");methPu5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``0`` ``=`` ``3``f``C``Y``h``t``e``m`` ``r``a``v\"))), " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``3``k``J``D``h``t``e``m`` ``+`` ``9``x``K``h``t``e``m`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``0`` ``=`` ``3``f``C``Y``h``t``e``m`` ``r``a``v\"))), " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\"/``*``@`` ``}``;``7``m``J``T``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``l``Q``h``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\"/``*``@`` ``}``;``)``7``i``P``h``t``e``m``(``6``l``J``E`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``j``P``E`" ascii
    $s11 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUr6 = methCu5[\"sp\"+\"lit\"](\"``\"); return methUr6[\"reverse\"]()" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``1``+``1``=``2``q``D``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\"/``*``@`` ``}``;``6``r``U``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``3``k``J``D``h``t``e``m`` ``+`` ``9``x``K``h``t``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``j``P``E`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\"}``;``h``t``a``P``t``r``o``h``S``.``5``u``C``S``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEJv3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``l``Q``h``t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}