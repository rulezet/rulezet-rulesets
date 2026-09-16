rule sig_20161216_109229ad2f5536aabe2e5d17a07dcdcc {
  meta:
    description = "datamaliciousorder - file 20161216_109229ad2f5536aabe2e5d17a07dcdcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeb7dcd0d5e8be607ee4e4270e1a661421b84496d7bf8f1e84e9b92fe7526b99"

  strings:
    $s1  = "function methVCa1(methGCk1) {eval(\"/*@cc_on var methYp1 = new Date() @*/\");methYp1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methSv8 = methGCk1[\"sp\"+\"lit\"](\"``\"); return methSv8[\"reverse\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``1``+``1``=``4``l``H``A``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``6``n``K``W``h``t``e``m`` ``+`` ``4``o``H``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\"/``*``@`` ``}``;``1``k``C``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\"/``*``@`` ``}``;``1``k``C``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``l``J``Z`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\"}``;``h``t``a``P``t``r``o``h``S``.``2``k``G``h``t``e``m`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\"/``*``@`` ``}``;``8``v``S``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\"/``*``@`` ``}``;``0``u``C``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``b``Z``h``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCa1(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}