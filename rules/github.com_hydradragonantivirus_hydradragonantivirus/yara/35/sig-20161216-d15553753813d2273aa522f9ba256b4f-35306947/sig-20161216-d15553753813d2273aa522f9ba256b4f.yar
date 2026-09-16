rule sig_20161216_d15553753813d2273aa522f9ba256b4f {
  meta:
    description = "datamaliciousorder - file 20161216_d15553753813d2273aa522f9ba256b4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "915d2e67ddfdf5b6772c68464188d6aaa65de3eb4a0a359bfa1b138e734910d4"

  strings:
    $s1  = "function methUi7(methEf4) {eval(\"/*@cc_on var methJId5 = new Date() @*/\");methJId5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methXt0 = methEf4[\"sp\"+\"lit\"](\"``\"); return methXt0[\"reverse\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``d``F``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\"}``;``h``t``a``P``t``r``o``h``S``.``8``t``F``P``h``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``0`` ``=`` ``4``j``K``K``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\"/``*``@`` ``}``;``9``o``D``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\"/``*``@`` ``}``;``)``6``h``E``Z``h``t``e``m``(``5``t``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``.`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\"/``*``@`` ``}``;``4``f``E``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\"/``*``@`` ``}``;``9``o``D``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``d``F``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUi7(\"/``*``@`` ``}``;``)``6``h``E``Z``h``t``e``m``(``5``t``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}