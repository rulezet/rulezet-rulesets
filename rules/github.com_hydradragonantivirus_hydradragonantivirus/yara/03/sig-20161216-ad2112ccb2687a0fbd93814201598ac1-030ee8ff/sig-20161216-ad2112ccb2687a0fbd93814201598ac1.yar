rule sig_20161216_ad2112ccb2687a0fbd93814201598ac1 {
  meta:
    description = "datamaliciousorder - file 20161216_ad2112ccb2687a0fbd93814201598ac1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0848378b9b2bbe40b5008303fb8532f8039fb7d77dcdbf24cc8bf984cbbc4d55"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZCi9 = methBt2[\"sp\"+\"lit\"](\"``\"); return methZCi9[\"reverse" ascii
    $s2  = "function methIq4(methBt2) {eval(\"/*@cc_on var methNAq7 = new Date() @*/\");methNAq7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\"/``*``@`` ``}``;``2``t``B``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\"/``*``@`` ``}``;``)``3``b``W``Q``h``t``e``m``(``6``e``B``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\"/``*``@`` ``}``;``9``i``C``Z``h``t``e``m`` ``n``r``u``t``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``z``C``S``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\"}``;``h``t``a``P``t``r``o``h``S``.``6``t``H``V``h``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``1``+``1``=``3``c``H``J``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s13 = "function methIq4(methBt2) {eval(\"/*@cc_on var methNAq7 = new Date() @*/\");methNAq7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``1``+``1``=``3``c``H``J``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIq4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``z``C``S``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}