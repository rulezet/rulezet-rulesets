rule sig_20161216_0665fe58522624f56d9e6906a3ab360c {
  meta:
    description = "datamaliciousorder - file 20161216_0665fe58522624f56d9e6906a3ab360c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92df9e44561edae0cce7cccdffd5cd9e2e43608d72520285ad920ef907e845f8"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMWz5 = methAo4[\"sp\"+\"lit\"](\"``\"); return methMWz5[\"revers" ascii
    $s2  = "function methCVt9(methAo4) {eval(\"/*@cc_on var methLWn0 = new Date() @*/\");methLWn0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\"}``;``h``t``a``P``t``r``o``h``S``.``5``f``Z``h``t``e``m`" ascii
    $s5  = "function methCVt9(methAo4) {eval(\"/*@cc_on var methLWn0 = new Date() @*/\");methLWn0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\"}``;``h``t``a``P``t``r``o``h``S``.``5``f``Z``h``t``e``m`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``2``u``F``h``t``e``m`` ``+`` ``0``t``M``h``t``e``m``=`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\"/``*``@`` ``}``;``5``z``W``M``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``2``u``F``h``t``e``m`` ``+`` ``0``t``M``h``t``e``m``=`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``1``+``1``=``9``x``G``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``i``E``W`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\"/``*``@`` ``}``;``5``z``W``M``h``t``e``m`` ``n``r``u``t`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``1``+``1``=``9``x``G``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``0`` ``=`` ``5``v``Y``E``h``t``e``m`` ``r``a``v\"))), " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCVt9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}