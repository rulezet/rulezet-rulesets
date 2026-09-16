rule sig_20161216_0a2c794cb0d89714c37c3b8f88deed4c {
  meta:
    description = "datamaliciousorder - file 20161216_0a2c794cb0d89714c37c3b8f88deed4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cca324a6a2ed9be92c6911ca793f62515245c45923f5a00ec807dadaa1f2df87"

  strings:
    $s1  = "function methYg7(methSv9) {eval(\"/*@cc_on var methBs2 = new Date() @*/\");methBs2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methYg7(methSv9) {eval(\"/*@cc_on var methBs2 = new Date() @*/\");methBs2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``8``m``Q``h``t``e``m`` ``+`` ``9``s``X``P``h``t``e``m``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\"/``*``@`` ``}``;``)``0``m``T``h``t``e``m``(``2``z``O``Y``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\"}``;``h``t``a``P``t``r``o``h``S``.``7``a``V``E``h``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\"/``*``@`` ``}``;``4``j``R``W``h``t``e``m`` ``n``r``u``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``t``O``A``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``t``O``A``" ascii
    $s18 = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methWRj4 = methSv9[\"sp\"+\"lit\"](\"``\"); return methWRj4[\"reverse\"](" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYg7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}