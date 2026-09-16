rule sig_20161216_326cc8b377f965985c024790e6bd4c9b {
  meta:
    description = "datamaliciousorder - file 20161216_326cc8b377f965985c024790e6bd4c9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd0516ec7cc0a8539db74143ddd126a98cdb22e5784a055d9cad72f454500fd0"

  strings:
    $s1  = "function methQa7(methGJq1) {eval(\"/*@cc_on var methPOq9 = new Date() @*/\");methPOq9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methXGp7 = methGJq1[\"sp\"+\"lit\"](\"``\"); return methXGp7[\"rever" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``.`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\"/``*``@`` ``}``;``)``8``h``E``X``h``t``e``m``(``5``y``Q``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\"/``*``@`` ``}``;``5``n``O``R``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``q``R``Q``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\"/``*``@`` ``}``;``7``p``G``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``9``y``C``T``h``t``e``m`` ``+`` ``6``b``D``Y``h``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``.`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\"/``*``@`` ``}``;``7``p``G``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``1``+``1``=``4``s``G``Y``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``o``K``h``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa7(\"}``;``h``t``a``P``t``r``o``h``S``.``6``z``Q``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}