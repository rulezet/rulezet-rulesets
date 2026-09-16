rule sig_20161216_c5012bb8e1aa0fa32b67d4e262819d46 {
  meta:
    description = "datamaliciousorder - file 20161216_c5012bb8e1aa0fa32b67d4e262819d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0987c38c74909c317fd2b819d784ecbea037af39c925a1913532fcbd8874f8fb"

  strings:
    $s1  = "function methNm5(methRx0) {eval(\"/*@cc_on var methVk4 = new Date() @*/\");methVk4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methNm5(methRx0) {eval(\"/*@cc_on var methVk4 = new Date() @*/\");methVk4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\"/``*``@`` ``}``;``)``3``w``L``U``h``t``e``m``(``1``t``H``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``0`` ``=`` ``5``h``Y``U``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``i``G``B``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\"/``*``@`` ``}``;``9``p``X``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``i``G``B``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\"/``*``@`` ``}``;``0``x``R``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\"/``*``@`` ``}``;``8``q``B``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``a``G``U``h``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``1``h``I``h``t``e``m`` ``+`` ``4``i``V``h``t``e``m``=``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\"/``*``@`` ``}``;``)``3``w``L``U``h``t``e``m``(``1``t``H``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNm5(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}