rule sig_20161216_c351af49dd7d4d8699136787c69c5531 {
  meta:
    description = "datamaliciousorder - file 20161216_c351af49dd7d4d8699136787c69c5531.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3193afdc7c70ead963be466dbefd3715028cb865bd1635f44f4c74e2fc205bc"

  strings:
    $s1  = "function methPn1(methMHf1) {eval(\"/*@cc_on var methYq0 = new Date() @*/\");methYq0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\"}``;``h``t``a``P``t``r``o``h``S``.``5``q``Z``h``t``e``m``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\"/``*``@`` ``}``;``1``f``H``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s7  = "function methPn1(methMHf1) {eval(\"/*@cc_on var methYq0 = new Date() @*/\");methYq0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\"/``*``@`` ``}``;``2``n``Q``P``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``0`` ``=`` ``6``v``N``F``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``h``O``W``h``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``2``g``V``F``h``t``e``m`` ``+`` ``8``u``B``h``t``e``m``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\"/``*``@`` ``}``;``0``l``N``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\";``2``g``V``F``h``t``e``m`` ``+`` ``8``u``B``h``t``e``m``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPn1(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}