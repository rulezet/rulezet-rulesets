rule sig_20161216_36a734bb1743bb39d355d5c06b200ee5 {
  meta:
    description = "datamaliciousorder - file 20161216_36a734bb1743bb39d355d5c06b200ee5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6087e7415f532bb2a2b2c7faa5c0085d6af8b980664d6ef01baecc97732972e0"

  strings:
    $s1  = "function methVn2(methOZk3) {eval(\"/*@cc_on var methRi2 = new Date() @*/\");methRi2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``4``o``Y``S``h``t``e``m`` ``+`` ``0``r``A``G``h``t``e``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"/``*``@`` ``}``;``5``d``Z``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``e``E``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"/``*``@`` ``}``;``5``d``Z``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"/``*``@`` ``}``;``)``1``i``E``O``h``t``e``m``(``2``q``L``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``e``E``h``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``1``+``1``=``8``s``O``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"/``*``@`` ``}``;``)``1``i``E``O``h``t``e``m``(``2``q``L``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``o``U``M``h``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``t``N``I``h``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"/``*``@`` ``}``;``9``b``U``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVn2(\"/``*``@`` ``}``;``9``b``U``h``t``e``m`` ``n``r``u``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}