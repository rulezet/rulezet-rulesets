rule sig_20161216_545398672e979b0c7eb97290c9795c59 {
  meta:
    description = "datamaliciousorder - file 20161216_545398672e979b0c7eb97290c9795c59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a6ed293ed75f4d373c4cf07d79c086be7d7e23ad71369b8dff219d3181507ff"

  strings:
    $s1  = "function methPBc9(methRRp0) {eval(\"/*@cc_on var methVKh7 = new Date() @*/\");methVKh7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBi5 = methRRp0[\"sp\"+\"lit\"](\"``\"); return methBi5[\"revers" ascii
    $s3  = "function methPBc9(methRRp0) {eval(\"/*@cc_on var methVKh7 = new Date() @*/\");methVKh7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\"/``*``@`` ``}``;``5``i``B``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\"/``*``@`` ``}``;``5``l``S``J``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\"/``*``@`` ``}``;``0``p``R``R``h``t``e``m`` ``n``r``u``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``x``K``P`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``7``c``Q``h``t``e``m`` ``+`` ``2``a``L``J``h``t``e``m`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``x``K``P`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPBc9(\"/``*``@`` ``}``;``5``i``B``h``t``e``m`` ``n``r``u``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}