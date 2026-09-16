rule sig_20161216_15125f6472ea7493a81337f1b3ac2f8e {
  meta:
    description = "datamaliciousorder - file 20161216_15125f6472ea7493a81337f1b3ac2f8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdd9a29dfccfa69d2fdd52f7443b34fa807f4565e3ac88ce54fb7bc5af969dfd"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methYn8 = methZs2[\"sp\"+\"lit\"](\"``\"); return methYn8[\"reverse" ascii
    $s2  = "function methZHh0(methZs2) {eval(\"/*@cc_on var methJNa3 = new Date() @*/\");methJNa3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "function methZHh0(methZs2) {eval(\"/*@cc_on var methJNa3 = new Date() @*/\");methJNa3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``c``S``h``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``1``+``1``=``9``s``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``1``+``1``=``9``s``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\"/``*``@`` ``}``;``)``9``b``D``h``t``e``m``(``7``t``A``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\"}``;``h``t``a``P``t``r``o``h``S``.``0``p``D``P``h``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZHh0(\"/``*``@`` ``}``;``7``f``K``h``t``e``m`` ``n``r``u``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}