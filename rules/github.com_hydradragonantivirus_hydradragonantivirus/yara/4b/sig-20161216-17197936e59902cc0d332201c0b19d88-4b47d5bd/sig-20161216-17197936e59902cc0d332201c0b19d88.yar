rule sig_20161216_17197936e59902cc0d332201c0b19d88 {
  meta:
    description = "datamaliciousorder - file 20161216_17197936e59902cc0d332201c0b19d88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b41cecf3aef920dc6bcc844e72087d258a8c6fe36b077dd37f964c14f6d9102"

  strings:
    $s1  = "function methXJx2(methNKd8) {eval(\"/*@cc_on var methTUz2 = new Date() @*/\");methTUz2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBo0 = methNKd8[\"sp\"+\"lit\"](\"``\"); return methBo0[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``r``X``h`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``5``c``M``h``t``e``m`` ``+`` ``9``f``I``F``h``t``e``m`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``d``M``X``h``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\"/``*``@`` ``}``;``)``6``c``F``h``t``e``m``(``1``d``F``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``d``A``N``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``)``\\x22``d``v``c``t``f``/``z``c``.``y``n``i``t``e``l" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\"/``*``@`` ``}``;``9``l``Y``Y``h``t``e``m`` ``n``r``u``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXJx2(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}