rule sig_20161216_f548c421acacdd1bcff655759b43c327 {
  meta:
    description = "datamaliciousorder - file 20161216_f548c421acacdd1bcff655759b43c327.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fc270095ad6314249b8ba7f58f0503c13c7aee05c21c69d637e20ecb231d08e"

  strings:
    $s1  = "function methYe1(methJBl3) {eval(\"/*@cc_on var methRt1 = new Date() @*/\");methRt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methKCj7 = methJBl3[\"sp\"+\"lit\"](\"``\"); return methKCj7[\"reverse\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\"/``*``@`` ``}``;``3``l``B``J``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\"/``*``@`` ``}``;``7``j``C``K``h``t``e``m`` ``n``r``u``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\"}``;``h``t``a``P``t``r``o``h``S``.``7``i``A``h``t``e``m``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``)``\\x22``d``v``c``t``f``/``z``c``.``y``n``i``t``e``l`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``0`` ``=`` ``6``q``E``I``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``w``D``h``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``w``D``h``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``3``o``B``h``t``e``m`` ``+`` ``3``f``B``h``t``e``m``=``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYe1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}