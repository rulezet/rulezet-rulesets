rule sig_20161216_6f738fbc521894f50e0c3b93e0a0f621 {
  meta:
    description = "datamaliciousorder - file 20161216_6f738fbc521894f50e0c3b93e0a0f621.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2c838ebdc48f18874183a50f150360c29cd0f49ac25423e681a7fb3bb0892e4"

  strings:
    $s1  = "function methHIa0(methSZb0) {eval(\"/*@cc_on var methKg7 = new Date() @*/\");methKg7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``0`` ``=`` ``0``d``V``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``1``+``1``=``5``i``K``J``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``0``b``Z``S``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``0`` ``=`` ``0``d``V``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``4``x``F``Q``h``t``e``m`` ``n``r``u``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``0``b``Z``S``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``)``1``t``M``h``t``e``m``(``7``b``I``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``)``1``t``M``h``t``e``m``(``7``b``I``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``t``V``h``t`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``2``n``L``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\"}``;``h``t``a``P``t``r``o``h``S``.``6``c``E``h``t``e``m`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``." ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHIa0(\";``7``z``S``R``h``t``e``m`` ``+`` ``4``s``I``W``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}