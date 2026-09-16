rule sig_20161216_6e33cf4e36397f8f09109695382dda3a {
  meta:
    description = "datamaliciousorder - file 20161216_6e33cf4e36397f8f09109695382dda3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fae42984f6a4aa06837d0879ea77cc840577e34c1ec9e918324187895794373c"

  strings:
    $s1  = "function methFSl0(methTa4) {eval(\"/*@cc_on var methXt0 = new Date() @*/\");methXt0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``0`` ``=`` ``1``s``P``X``h``t``e``m`` ``r``a``v\"))), " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``1``+``1``=``9``e``I``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``l``I``P``h``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\"/``*``@`` ``}``;``)``3``i``Y``h``t``e``m``(``8``l``N``J`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\"/``*``@`` ``}``;``9``t``J``Z``h``t``e``m`` ``n``r``u``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\"/``*``@`` ``}``;``9``t``J``Z``h``t``e``m`` ``n``r``u``t`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``o``V``S``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``l``I``P``h``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\"/``*``@`` ``}``;``0``b``I``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s17 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methIb0 = methTa4[\"sp\"+\"lit\"](\"``\"); return methIb0[\"reverse\"]()" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``1``+``1``=``9``e``I``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFSl0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}