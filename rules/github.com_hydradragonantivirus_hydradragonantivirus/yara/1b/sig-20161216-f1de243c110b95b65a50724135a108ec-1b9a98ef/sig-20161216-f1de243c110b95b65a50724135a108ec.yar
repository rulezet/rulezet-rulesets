rule sig_20161216_f1de243c110b95b65a50724135a108ec {
  meta:
    description = "datamaliciousorder - file 20161216_f1de243c110b95b65a50724135a108ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e63c5c890f6d88213121dae8f1575111c2dba5facbf3360f89309c95bd80cc6"

  strings:
    $s1  = "function methIu9(methRRs0) {eval(\"/*@cc_on var methKy6 = new Date() @*/\");methKy6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\"/``*``@`` ``}``;``)``5``w``J``h``t``e``m``(``2``f``B``H``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\"}``;``h``t``a``P``t``r``o``h``S``.``6``o``N``T``h``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``)``\\x22``t``x``d``f``4``b``l``j``/``m``o``c``.``r``a`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``0``v``Q``h``t``e``m`` ``+`` ``5``r``I``h``t``e``m``=``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s12 = "function methIu9(methRRs0) {eval(\"/*@cc_on var methKy6 = new Date() @*/\");methKy6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\"/``*``@`` ``}``;``0``s``R``R``h``t``e``m`` ``n``r``u``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\"/``*``@`` ``}``;``3``g``Q``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIu9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}