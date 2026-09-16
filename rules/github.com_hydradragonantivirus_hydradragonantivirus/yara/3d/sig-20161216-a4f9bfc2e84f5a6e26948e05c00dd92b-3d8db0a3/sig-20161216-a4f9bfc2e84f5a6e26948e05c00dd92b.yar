rule sig_20161216_a4f9bfc2e84f5a6e26948e05c00dd92b {
  meta:
    description = "datamaliciousorder - file 20161216_a4f9bfc2e84f5a6e26948e05c00dd92b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d9486907d7a2a85d10040086e2c6ad45ad79474355541d093e710dd94c53d39"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZLv7 = methPg7[\"sp\"+\"lit\"](\"``\"); return methZLv7[\"revers" ascii
    $s2  = "function methCYn9(methPg7) {eval(\"/*@cc_on var methLMv5 = new Date() @*/\");methLMv5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``8``k``C``G``h``t``e``m`` ``+`` ``0``s``U``S``h``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``8``k``C``G``h``t``e``m`` ``+`` ``0``s``U``S``h``t``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\"/``*``@`` ``}``;``7``v``L``Z``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``o``Q``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``1``+``1``=``7``f``M``R``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``o``Q``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCYn9(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}