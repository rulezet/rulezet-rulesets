rule sig_20161215_dbeb4292454141456f8c90e93dc3e5d3 {
  meta:
    description = "datamaliciousorder - file 20161215_dbeb4292454141456f8c90e93dc3e5d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "920012ab2f4a2c2881e3439af92462938d90cc360624986a6e7517b03d06600c"

  strings:
    $s1  = "function cheburgenKJp0(cheburgenWs1) {eval(\"/*@cc_on var cheburgenGVx4 = new Date() @*/\");cheburgenGVx4[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``u``Z``n" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\"}``;``h``t``a``P``t``r``o``h``S``.``6``w``E``n``e``g``r" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``1``x``P``H``n``e``g``r``u``b``e``h``c`` ``+`` ``8``g" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\"/``*``@`` ``}``;``1``s``W``n``e``g``r``u``b``e``h``c`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\"/``*``@`` ``}``;``8``n``I``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``1``+``1``=``7``w``L``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\"/``*``@`` ``}``;``1``f``B``Y``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\"}``;``h``t``a``P``t``r``o``h``S``.``6``w``E``n``e``g``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\"/``*``@`` ``}``;``1``s``W``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``)``\\x22``\\x22`` ``+`` ``7``v``N``n``e``g``r``u``b`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``)``\\x22``i``t``v``j``a``7``a``b``l``/``m``o``c``.``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKJp0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}