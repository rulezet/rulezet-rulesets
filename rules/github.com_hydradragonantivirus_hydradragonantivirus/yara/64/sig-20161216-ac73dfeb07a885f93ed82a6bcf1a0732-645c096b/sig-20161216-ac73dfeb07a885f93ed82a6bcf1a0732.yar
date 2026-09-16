rule sig_20161216_ac73dfeb07a885f93ed82a6bcf1a0732 {
  meta:
    description = "datamaliciousorder - file 20161216_ac73dfeb07a885f93ed82a6bcf1a0732.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d101224c29a110be4f138a1b5d318fa740723c5a36d4980e95872d711ae100e"

  strings:
    $s1  = "function methCRs2(methCTz7) {eval(\"/*@cc_on var methCLq4 = new Date() @*/\");methCLq4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methAEs6 = methCTz7[\"sp\"+\"lit\"](\"``\"); return methAEs6[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``1``+``1``=``7``b``T``N``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\"}``;``h``t``a``P``t``r``o``h``S``.``5``v``W``Y``h``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\"/``*``@`` ``}``;``0``k``B``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``5``h``O``Y``h``t``e``m`` ``+`` ``6``z``L``S``h``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``g``V``Q``h`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``0`` ``=`` ``0``o``H``W``h``t``e``m`` ``r``a``v\"))), " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``c``W``W`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\"/``*``@`` ``}``;``6``s``E``A``h``t``e``m`` ``n``r``u``t`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\"/``*``@`` ``}``;``)``5``i``A``h``t``e``m``(``1``o``G``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCRs2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``g``V``Q``h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}