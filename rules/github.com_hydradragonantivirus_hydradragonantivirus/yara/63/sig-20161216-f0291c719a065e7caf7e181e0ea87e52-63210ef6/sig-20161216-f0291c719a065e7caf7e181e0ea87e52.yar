rule sig_20161216_f0291c719a065e7caf7e181e0ea87e52 {
  meta:
    description = "datamaliciousorder - file 20161216_f0291c719a065e7caf7e181e0ea87e52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "118ff7f575f0cd86cbfff55fd345957a73f6aabf152ed30519a03920c4e4fe25"

  strings:
    $s1  = "function methAYe8(methBTu1) {eval(\"/*@cc_on var methDz4 = new Date() @*/\");methDz4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\"/``*``@`` ``}``;``0``l``Z``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``c``B``h`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``c``B``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\"}``;``h``t``a``P``t``r``o``h``S``.``1``l``N``R``h``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``1``+``1``=``1``p``W``E``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\"/``*``@`` ``}``;``1``u``T``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\"/``*``@`` ``}``;``)``0``r``N``h``t``e``m``(``7``q``J``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "function methAYe8(methBTu1) {eval(\"/*@cc_on var methDz4 = new Date() @*/\");methDz4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\"/``*``@`` ``}``;``1``u``T``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYe8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methKTf6 = methBTu1[\"sp\"+\"lit\"](\"``\"); return methKTf6[\"reverse" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}