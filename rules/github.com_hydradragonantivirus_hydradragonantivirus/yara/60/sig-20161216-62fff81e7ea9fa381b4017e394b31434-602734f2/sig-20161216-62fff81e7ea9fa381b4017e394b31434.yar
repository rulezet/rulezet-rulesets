rule sig_20161216_62fff81e7ea9fa381b4017e394b31434 {
  meta:
    description = "datamaliciousorder - file 20161216_62fff81e7ea9fa381b4017e394b31434.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8aa40e625c386db50c2a6b7dbd4d41cef525117c3719207741cab4bedaad6ac"

  strings:
    $s1  = "function methRl2(methTVs0) {eval(\"/*@cc_on var methZi2 = new Date() @*/\");methZi2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``9``f``R``h``t``e``m`` ``+`` ``8``w``U``M``h``t``e``m``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``z``B``Q``h``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``\\x22``4``m``e``j``f``/``a``b``.``m``o``c``.``n``o`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\"/``*``@`` ``}``;``1``n``M``W``h``t``e``m`` ``n``r``u``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``0`` ``=`` ``9``j``S``W``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``1``+``1``=``0``a``F``W``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``v``U``F``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``\\x22``g``j``g``i``0``/``m``o``c``.``g``n``o``s``n`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\"/``*``@`` ``}``;``1``n``M``W``h``t``e``m`` ``n``r``u``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``1``+``1``=``0``a``F``W``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRl2(\";``)``\\x22``g``j``g``i``0``/``m``o``c``.``g``n``o``s``n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}