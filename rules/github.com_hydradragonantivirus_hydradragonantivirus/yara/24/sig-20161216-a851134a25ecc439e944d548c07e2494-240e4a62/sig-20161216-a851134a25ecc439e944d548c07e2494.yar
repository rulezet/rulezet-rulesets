rule sig_20161216_a851134a25ecc439e944d548c07e2494 {
  meta:
    description = "datamaliciousorder - file 20161216_a851134a25ecc439e944d548c07e2494.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cbebc9b2d64c476b37ecaf044fd8f1076e096a35e41ef69fb697546156f965c"

  strings:
    $s1  = "function methQl2(methXQc3) {eval(\"/*@cc_on var methUQf5 = new Date() @*/\");methUQf5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methNr3 = methXQc3[\"sp\"+\"lit\"](\"``\"); return methNr3[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\";``1``+``1``=``7``d``Z``L``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"/``*``@`` ``}``;``3``r``N``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"/``*``@`` ``}``;``3``e``W``S``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``u``C``h``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"}``;``h``t``a``P``t``r``o``h``S``.``7``y``Q``h``t``e``m``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"/``*``@`` ``}``;``3``r``N``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``z``X``Q``h``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"/``*``@`` ``}``;``3``c``Q``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\"/``*``@`` ``}``;``3``e``W``S``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQl2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}