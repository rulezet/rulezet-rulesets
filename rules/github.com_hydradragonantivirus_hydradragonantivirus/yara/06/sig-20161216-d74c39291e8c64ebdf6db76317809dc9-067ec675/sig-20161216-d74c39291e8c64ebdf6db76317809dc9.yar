rule sig_20161216_d74c39291e8c64ebdf6db76317809dc9 {
  meta:
    description = "datamaliciousorder - file 20161216_d74c39291e8c64ebdf6db76317809dc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dd4a40adc18c50bf5e9add3a26ba5ed12b87daccca7ea907c503c5b532d4a6a"

  strings:
    $s1  = "function methOk6(methJMj8) {eval(\"/*@cc_on var methZn2 = new Date() @*/\");methZn2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``1``p``L``S``h``t``e``m`` ``+`` ``6``l``W``h``t``e``m``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``1``+``1``=``4``s``Q``Q``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\"}``;``h``t``a``P``t``r``o``h``S``.``0``d``F``h``t``e``m``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m`" ascii
    $s11 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methEh3 = methJMj8[\"sp\"+\"lit\"](\"``\"); return methEh3[\"reverse\"](" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\"/``*``@`` ``}``;``3``h``E``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\"/``*``@`` ``}``;``8``j``M``J``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s`" ascii
    $s18 = "function methOk6(methJMj8) {eval(\"/*@cc_on var methZn2 = new Date() @*/\");methZn2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOk6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``h``M``h``t``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}