rule sig_20161216_b7aa66f155f190f02e35aeea89093d6b {
  meta:
    description = "datamaliciousorder - file 20161216_b7aa66f155f190f02e35aeea89093d6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2560f22e330b0bd511a3b50500d75655f3b333bf457a04cef6c677eda0b2a50c"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methOBv7 = methJTa9[\"sp\"+\"lit\"](\"``\"); return methOBv7[\"reve" ascii
    $s2  = "function methDUp5(methJTa9) {eval(\"/*@cc_on var methPXy3 = new Date() @*/\");methPXy3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\"}``;``h``t``a``P``t``r``o``h``S``.``9``r``L``h``t``e``m`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\"/``*``@`` ``}``;``9``a``T``J``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\"}``;``h``t``a``P``t``r``o``h``S``.``9``r``L``h``t``e``m`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``1``+``1``=``9``d``T``Z``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\"/``*``@`` ``}``;``)``8``c``V``B``h``t``e``m``(``5``a``H`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``s``Y``h``t`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``0`` ``=`` ``0``r``K``E``h``t``e``m`` ``r``a``v\"))), " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``c``N``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\"/``*``@`` ``}``;``1``p``W``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDUp5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}