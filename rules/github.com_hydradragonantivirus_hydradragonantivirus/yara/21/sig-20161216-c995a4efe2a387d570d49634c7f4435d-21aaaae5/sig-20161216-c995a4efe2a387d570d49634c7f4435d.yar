rule sig_20161216_c995a4efe2a387d570d49634c7f4435d {
  meta:
    description = "datamaliciousorder - file 20161216_c995a4efe2a387d570d49634c7f4435d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9744006aa3f70e174a1dc20021506aeefdd5879a1a56cb24f8d2361f698a5ac5"

  strings:
    $s1  = "function methWUu6(methPf4) {eval(\"/*@cc_on var methYk2 = new Date() @*/\");methYk2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``1``+``1``=``5``e``T``C``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"/``*``@`` ``}``;``4``f``P``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``a``H``h``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"/``*``@`` ``}``;``7``x``V``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``)``\\x22``v``h``i``g``n``/``u``a``.``m``o``c``.``e``m" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``1``q``V``P``h``t``e``m`` ``+`` ``0``o``Q``L``h``t``e`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``)``\\x22``v``h``i``g``n``/``u``a``.``m``o``c``.``e``m" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``e``H``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``a``H``h``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\";``1``q``V``P``h``t``e``m`` ``+`` ``0``o``Q``L``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"}``;``h``t``a``P``t``r``o``h``S``.``7``e``M``R``h``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWUu6(\"}``;``h``t``a``P``t``r``o``h``S``.``7``e``M``R``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}