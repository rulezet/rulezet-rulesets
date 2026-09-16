rule sig_20161216_11550a81514de6ea5de953b4282fe756 {
  meta:
    description = "datamaliciousorder - file 20161216_11550a81514de6ea5de953b4282fe756.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "298f71a905911aa4f163b6804371690f451215d57a84bd1b41b2a03b873fdb20"

  strings:
    $s1  = "function methWi7(methWf2) {eval(\"/*@cc_on var methURw0 = new Date() @*/\");methURw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methXVm7 = methWf2[\"sp\"+\"lit\"](\"``\"); return methXVm7[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"/``*``@`` ``}``;``1``u``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``z``C``h``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"/``*``@`` ``}``;``2``f``W``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\";``4``c``T``G``h``t``e``m`` ``+`` ``4``d``U``K``h``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"/``*``@`` ``}``;``1``u``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``h``A``T``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"}``;``h``t``a``P``t``r``o``h``S``.``1``h``D``F``h``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"/``*``@`` ``}``;``7``m``V``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``h``A``T``h``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\";``0`` ``=`` ``9``i``L``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"/``*``@`` ``}``;``)``7``p``U``h``t``e``m``(``6``e``S``h``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWi7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}