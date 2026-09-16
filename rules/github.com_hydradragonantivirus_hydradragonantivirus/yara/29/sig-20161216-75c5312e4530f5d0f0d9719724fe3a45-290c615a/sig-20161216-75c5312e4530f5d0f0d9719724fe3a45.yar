rule sig_20161216_75c5312e4530f5d0f0d9719724fe3a45 {
  meta:
    description = "datamaliciousorder - file 20161216_75c5312e4530f5d0f0d9719724fe3a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80b179ff94adb57d1b5368a2e62cc5b53c243b4e79ddb77f01463f3c57b1e4b5"

  strings:
    $s1  = "function methANd5(methUl4) {eval(\"/*@cc_on var methHUn1 = new Date() @*/\");methHUn1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methHOl6 = methUl4[\"sp\"+\"lit\"](\"``\"); return methHOl6[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\"}``;``h``t``a``P``t``r``o``h``S``.``9``w``T``h``t``e``m`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``0`` ``=`` ``1``z``E``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``q``G``h``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``z``R``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\"/``*``@`` ``}``;``3``h``V``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "function methANd5(methUl4) {eval(\"/*@cc_on var methHUn1 = new Date() @*/\");methHUn1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``1``+``1``=``4``a``W``D``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\"/``*``@`` ``}``;``6``l``O``H``h``t``e``m`` ``n``r``u``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methANd5(\";``)``\\x22``4``5``n``b``o``n``j``/``m``o``c``.``a``f``o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}