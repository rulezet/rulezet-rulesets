rule sig_20161215_2a0d07585d4ac26b531c55e9ae55d097 {
  meta:
    description = "datamaliciousorder - file 20161215_2a0d07585d4ac26b531c55e9ae55d097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c597ff7f32bac6059cee2526fe4c5c532b2f70f8702cc876ffbbba879382b52c"

  strings:
    $s1  = "function cheburgenEf2(cheburgenKu8) {eval(\"/*@cc_on var cheburgenPZp7 = new Date() @*/\");cheburgenPZp7[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenPZp7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenWi2 = cheburgenKu8[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``\\x22``\\x22`` ``+`` ``2``q``W``n``e``g``r``u``b``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``." ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\"/``*``@`` ``}``;``1``w``F``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``d``A``R`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\"}``;``h``t``a``P``t``r``o``h``S``.``8``t``C``B``n``e``g`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``d``A``R`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\"/``*``@`` ``}``;``)``2``m``W``B``n``e``g``r``u``b``e``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``8``e``D``X``n``e``g``r``u``b``e``h``c`` ``+`` ``2``u`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEf2(\"\")), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}