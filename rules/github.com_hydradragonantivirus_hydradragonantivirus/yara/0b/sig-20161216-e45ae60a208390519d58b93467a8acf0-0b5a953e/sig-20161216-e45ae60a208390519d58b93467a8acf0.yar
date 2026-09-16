rule sig_20161216_e45ae60a208390519d58b93467a8acf0 {
  meta:
    description = "datamaliciousorder - file 20161216_e45ae60a208390519d58b93467a8acf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bc74c1123ee2c31b0da6956aa6664d3eb40122b73db05298109690b32502675"

  strings:
    $s1  = "function methBz3(methBAi6) {eval(\"/*@cc_on var methGq3 = new Date() @*/\");methGq3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"/``*``@`` ``}``;``4``i``K``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"}``;``h``t``a``P``t``r``o``h``S``.``0``s``S``I``h``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"/``*``@`` ``}``;``4``i``K``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"/``*``@`` ``}``;``)``8``c``P``h``t``e``m``(``2``w``A``A``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``l``J``D``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"/``*``@`` ``}``;``6``i``A``B``h``t``e``m`` ``n``r``u``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\"}``;``h``t``a``P``t``r``o``h``S``.``0``s``S``I``h``t``e``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBz3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}