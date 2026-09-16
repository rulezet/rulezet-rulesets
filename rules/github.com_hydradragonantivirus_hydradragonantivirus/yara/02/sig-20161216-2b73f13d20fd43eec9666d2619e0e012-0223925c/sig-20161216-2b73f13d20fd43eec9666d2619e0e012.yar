rule sig_20161216_2b73f13d20fd43eec9666d2619e0e012 {
  meta:
    description = "datamaliciousorder - file 20161216_2b73f13d20fd43eec9666d2619e0e012.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47d7a3c294505a182c201ba8d0c1beaec79e839b8f7732401dc4ea9d4a0bf2ca"

  strings:
    $s1  = "function methJv1(methJEt1) {eval(\"/*@cc_on var methXp5 = new Date() @*/\");methXp5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``4``x``T``h``t``e``m`` ``+`` ``3``a``J``B``h``t``e``m``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``v``T``Z``h``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``c``W``B``h``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\"/``*``@`` ``}``;``1``t``E``J``h``t``e``m`` ``n``r``u``t``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``r``F``S``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\"/``*``@`` ``}``;``)``9``k``E``h``t``e``m``(``9``e``A``h``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``.`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``c``W``B``h``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``1``+``1``=``4``b``M``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``0`` ``=`` ``4``d``Y``L``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJv1(\"/``*``@`` ``}``;``)``9``k``E``h``t``e``m``(``9``e``A``h``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}