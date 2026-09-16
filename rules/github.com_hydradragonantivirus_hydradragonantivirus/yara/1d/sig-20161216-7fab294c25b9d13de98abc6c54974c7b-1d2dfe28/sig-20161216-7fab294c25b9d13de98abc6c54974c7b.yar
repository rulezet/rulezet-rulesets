rule sig_20161216_7fab294c25b9d13de98abc6c54974c7b {
  meta:
    description = "datamaliciousorder - file 20161216_7fab294c25b9d13de98abc6c54974c7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccf36abf8d2a1f0333a6547cf747193c96c16d498dd1dcd81f756e4bd4f65c8f"

  strings:
    $s1  = "function methKg3(methRUe9) {eval(\"/*@cc_on var methEOz9 = new Date() @*/\");methEOz9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methTEw9 = methRUe9[\"sp\"+\"lit\"](\"``\"); return methTEw9[\"rever" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``7``s``F``L``h``t``e``m`` ``+`` ``6``z``X``h``t``e``m``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``)``\\x22``0``0``7``k``d``u``2``2``z``z``/``g``r``o``.`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``0`` ``=`` ``6``o``Q``V``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``1``+``1``=``5``u``V``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``7``s``F``L``h``t``e``m`` ``+`` ``6``z``X``h``t``e``m``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\"/``*``@`` ``}``;``6``p``M``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\"/``*``@`` ``}``;``9``w``E``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\"/``*``@`` ``}``;``6``p``M``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``t``N``h``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\"/``*``@`` ``}``;``9``e``U``R``h``t``e``m`` ``n``r``u``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\"/``*``@`` ``}``;``9``e``U``R``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKg3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}