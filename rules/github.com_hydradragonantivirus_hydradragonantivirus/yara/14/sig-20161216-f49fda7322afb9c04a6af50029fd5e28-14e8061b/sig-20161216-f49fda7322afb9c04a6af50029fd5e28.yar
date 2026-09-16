rule sig_20161216_f49fda7322afb9c04a6af50029fd5e28 {
  meta:
    description = "datamaliciousorder - file 20161216_f49fda7322afb9c04a6af50029fd5e28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd443ab499c5ec8f9609e11eda37d8e082966023ecaadd5acce2aa28090d809"

  strings:
    $s1  = "function methOw1(methISt5) {eval(\"/*@cc_on var methIr5 = new Date() @*/\");methIr5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"/``*``@`` ``}``;``2``o``A``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"/``*``@`` ``}``;``5``t``S``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``o``D``I``h``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``l``T``A``h``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``r``K``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``l``T``A``h``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"/``*``@`` ``}``;``0``i``J``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\"/``*``@`` ``}``;``2``o``A``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``8``l``I``G``h``t``e``m`` ``+`` ``7``q``X``E``h``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOw1(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o`" ascii
    $s20 = "function methOw1(methISt5) {eval(\"/*@cc_on var methIr5 = new Date() @*/\");methIr5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}