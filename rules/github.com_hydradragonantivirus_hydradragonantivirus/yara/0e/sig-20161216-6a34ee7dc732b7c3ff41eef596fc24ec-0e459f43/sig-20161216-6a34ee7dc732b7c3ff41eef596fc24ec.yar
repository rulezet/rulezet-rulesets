rule sig_20161216_6a34ee7dc732b7c3ff41eef596fc24ec {
  meta:
    description = "datamaliciousorder - file 20161216_6a34ee7dc732b7c3ff41eef596fc24ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "049766325c5ab1ce7ebe9ac1861b95638dd27a292e7e63e9e2954223c0619eaf"

  strings:
    $s1  = "function methQCl5(methMYn5) {eval(\"/*@cc_on var methYu0 = new Date() @*/\");methYu0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``m``C``M``h`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``3``n``O``L``h``t``e``m`` ``+`` ``6``t``N``h``t``e``m`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``m``C``M``h`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\"/``*``@`` ``}``;``1``k``O``A``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``)``\\x22``l``k``w``x``q``n``p``w``q``/``x``m``.``m``o" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``." ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\"/``*``@`` ``}``;``1``k``O``A``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``." ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``1``+``1``=``5``t``U``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\"/``*``@`` ``}``;``5``n``Y``M``h``t``e``m`` ``n``r``u``t`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``j``L``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQCl5(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}