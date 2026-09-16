rule sig_20161216_6bc0fe7c93f2d4c5ff64105a61a6eb68 {
  meta:
    description = "datamaliciousorder - file 20161216_6bc0fe7c93f2d4c5ff64105a61a6eb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5e11414a65b5e5881b4091f80102d08b04e1bd80458db6a6e33a483e6ddae36"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBJz0 = methQTk0[\"sp\"+\"lit\"](\"``\"); return methBJz0[\"rever" ascii
    $s2  = "function methNv2(methQTk0) {eval(\"/*@cc_on var methDQr5 = new Date() @*/\");methDQr5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``\\x22``d``i``e``z``d``f``l``z``/``z``c``.``r``a``z`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``v``A``K``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\"}``;``h``t``a``P``t``r``o``h``S``.``6``h``J``P``h``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``\\x22``0``0``7``k``d``u``2``2``z``z``/``g``r``o``.`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``\\x22``4``z``p``i``r``a``z``/``m``o``c``.``a``d``i`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``1``+``1``=``4``l``C``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s14 = "function methNv2(methQTk0) {eval(\"/*@cc_on var methDQr5 = new Date() @*/\");methDQr5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``v``A``K``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\"/``*``@`` ``}``;``9``u``X``D``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNv2(\";``)``\\x22``d``i``e``z``d``f``l``z``/``z``c``.``r``a``z`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}