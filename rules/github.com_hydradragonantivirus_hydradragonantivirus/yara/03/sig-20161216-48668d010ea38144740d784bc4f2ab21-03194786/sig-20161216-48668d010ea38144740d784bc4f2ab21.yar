rule sig_20161216_48668d010ea38144740d784bc4f2ab21 {
  meta:
    description = "datamaliciousorder - file 20161216_48668d010ea38144740d784bc4f2ab21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37f7bac1c22c150b9c0f3b5a9b2a7c159e4e07f4ff807d26a5b59f7e8725aa74"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMj9 = methUb7[\"sp\"+\"lit\"](\"``\"); return methMj9[\"reverse\"]" ascii
    $s2  = "function methUl4(methUb7) {eval(\"/*@cc_on var methVUu0 = new Date() @*/\");methVUu0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``0`` ``=`` ``1``s``S``M``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\"/``*``@`` ``}``;``7``b``U``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``7``l``N``S``h``t``e``m`` ``+`` ``6``t``U``h``t``e``m``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\"/``*``@`` ``}``;``9``j``M``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``d``K``h``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``d``K``h``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\"/``*``@`` ``}``;``)``4``b``D``h``t``e``m``(``4``z``C``H``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUl4(\"}``;``h``t``a``P``t``r``o``h``S``.``2``a``J``R``h``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}