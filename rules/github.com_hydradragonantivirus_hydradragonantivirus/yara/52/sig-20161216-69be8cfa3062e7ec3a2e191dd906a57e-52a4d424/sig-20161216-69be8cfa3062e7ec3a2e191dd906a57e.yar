rule sig_20161216_69be8cfa3062e7ec3a2e191dd906a57e {
  meta:
    description = "datamaliciousorder - file 20161216_69be8cfa3062e7ec3a2e191dd906a57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1957dc272f96ba1d1e8c2fd21d2c37dbaa46922f632e5d4f84902c85de1c31d5"

  strings:
    $s1  = "function methLVp2(methGd4) {eval(\"/*@cc_on var methWh5 = new Date() @*/\");methWh5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"/``*``@`` ``}``;``2``l``M``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"/``*``@`` ``}``;``3``b``Y``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``v``R``G``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"/``*``@`` ``}``;``)``2``s``S``h``t``e``m``(``6``e``E``h`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"/``*``@`` ``}``;``4``d``G``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"/``*``@`` ``}``;``4``d``G``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``0`` ``=`` ``2``l``B``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"}``;``h``t``a``P``t``r``o``h``S``.``5``i``Z``B``h``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"/``*``@`` ``}``;``)``2``s``S``h``t``e``m``(``6``e``E``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``f``M``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLVp2(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}