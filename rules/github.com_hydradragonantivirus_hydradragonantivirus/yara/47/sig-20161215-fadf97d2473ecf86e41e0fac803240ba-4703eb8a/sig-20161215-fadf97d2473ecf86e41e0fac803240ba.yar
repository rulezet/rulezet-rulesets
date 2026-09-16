rule sig_20161215_fadf97d2473ecf86e41e0fac803240ba {
  meta:
    description = "datamaliciousorder - file 20161215_fadf97d2473ecf86e41e0fac803240ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41a35fe264238e206dce2db03d4fa672046a6d26157374f1787e8e3f4524b158"

  strings:
    $s1  = "function cheburgenIn3(cheburgenPu3) {eval(\"/*@cc_on var cheburgenTOu3 = new Date() @*/\");cheburgenTOu3[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenTOu3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenAz8 = cheburgenPu3[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``1``+``1``=``8``m``H``W``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\"/``*``@`` ``}``;``8``z``A``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``0`` ``=`` ``5``s``B``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\"}``;``h``t``a``P``t``r``o``h``S``.``3``n``O``n``e``g``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``q``C``L`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``)``\\x22``4``j``g``a``q``s``/``m``o``c``.``h``c``e``t" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``y``L``X``n`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``g" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``g" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIn3(\"\")), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}