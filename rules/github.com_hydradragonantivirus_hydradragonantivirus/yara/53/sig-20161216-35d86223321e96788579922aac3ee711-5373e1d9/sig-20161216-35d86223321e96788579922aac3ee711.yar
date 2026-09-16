rule sig_20161216_35d86223321e96788579922aac3ee711 {
  meta:
    description = "datamaliciousorder - file 20161216_35d86223321e96788579922aac3ee711.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6a9eab976595eae290528ffc276ae79ae9f88af7708bf8ec83132f9b5bd1b36"

  strings:
    $s1  = "function methYJn4(methWVf3) {eval(\"/*@cc_on var methBy0 = new Date() @*/\");methBy0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``0`` ``=`` ``3``d``Q``F``h``t``e``m`` ``r``a``v\"))), " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``f``J``h`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``d``A``O``h`" ascii
    $s6  = "function methYJn4(methWVf3) {eval(\"/*@cc_on var methBy0 = new Date() @*/\");methBy0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\"}``;``h``t``a``P``t``r``o``h``S``.``5``l``W``h``t``e``m`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\"/``*``@`` ``}``;``1``e``B``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\"/``*``@`` ``}``;``4``e``A``K``h``t``e``m`` ``n``r``u``t`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``." ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``0`` ``=`` ``3``d``Q``F``h``t``e``m`` ``r``a``v\"))), " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBe1 = methWVf3[\"sp\"+\"lit\"](\"``\"); return methBe1[\"reverse\"]" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\"/``*``@`` ``}``;``)``5``z``M``R``h``t``e``m``(``4``r``C`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\"/``*``@`` ``}``;``3``f``V``W``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYJn4(\"/``*``@`` ``}``;``1``e``B``h``t``e``m`` ``n``r``u``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}