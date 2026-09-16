rule sig_20161216_ab8c34072e015f7e0489d1d10cb4e4e3 {
  meta:
    description = "datamaliciousorder - file 20161216_ab8c34072e015f7e0489d1d10cb4e4e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca9e31deae89c893a603d267c4e91a6f6017ad36162d314f02340f146fd04407"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methKOg7 = methAa6[\"sp\"+\"lit\"](\"``\"); return methKOg7[\"reverse" ascii
    $s2  = "function methNu2(methAa6) {eval(\"/*@cc_on var methOEf8 = new Date() @*/\");methOEf8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "function methNu2(methAa6) {eval(\"/*@cc_on var methOEf8 = new Date() @*/\");methOEf8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``1``+``1``=``5``f``X``E``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\"/``*``@`` ``}``;``5``s``Q``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``i``L``V``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``.`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\"}``;``h``t``a``P``t``r``o``h``S``.``7``d``M``h``t``e``m``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\"/``*``@`` ``}``;``)``9``v``V``B``h``t``e``m``(``7``p``I``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\"/``*``@`` ``}``;``6``a``A``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\"/``*``@`` ``}``;``7``g``O``K``h``t``e``m`` ``n``r``u``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``3``l``D``I``h``t``e``m`` ``+`` ``6``r``J``h``t``e``m``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\";``1``+``1``=``5``f``X``E``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNu2(\"/``*``@`` ``}``;``)``9``v``V``B``h``t``e``m``(``7``p``I``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}