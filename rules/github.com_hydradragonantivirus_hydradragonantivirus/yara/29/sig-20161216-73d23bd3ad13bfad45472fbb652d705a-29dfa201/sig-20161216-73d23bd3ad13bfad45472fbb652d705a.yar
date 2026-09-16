rule sig_20161216_73d23bd3ad13bfad45472fbb652d705a {
  meta:
    description = "datamaliciousorder - file 20161216_73d23bd3ad13bfad45472fbb652d705a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8db173137230030a6e8de1d01811d531798653c6154641cfdc42a3f0abdae6ee"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methPLk0 = methFy6[\"sp\"+\"lit\"](\"``\"); return methPLk0[\"revers" ascii
    $s2  = "function methYXu6(methFy6) {eval(\"/*@cc_on var methSRe1 = new Date() @*/\");methSRe1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``1``+``1``=``5``k``I``S``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``m``Z``A`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\"}``;``h``t``a``P``t``r``o``h``S``.``3``r``Q``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\"}``;``h``t``a``P``t``r``o``h``S``.``3``r``Q``h``t``e``m`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``)``\\x22``v``h``i``g``n``/``u``a``.``m``o``c``.``e``m" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``j``L``h``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\"/``*``@`` ``}``;``6``y``F``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYXu6(\";``8``b``W``h``t``e``m`` ``+`` ``7``z``V``H``h``t``e``m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}