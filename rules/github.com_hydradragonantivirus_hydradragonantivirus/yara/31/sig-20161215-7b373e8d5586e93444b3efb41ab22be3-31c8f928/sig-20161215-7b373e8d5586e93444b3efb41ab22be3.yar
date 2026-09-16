rule sig_20161215_7b373e8d5586e93444b3efb41ab22be3 {
  meta:
    description = "datamaliciousorder - file 20161215_7b373e8d5586e93444b3efb41ab22be3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69353cd248261f736d64462263a2831fe97f5b46fb80f023e076fa7f7b0b1a8c"

  strings:
    $s1  = "\"20\");if (cheburgenLl0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenMn4 = cheburgenSXg6[\"split\"](\"`" ascii
    $s2  = "function cheburgenWHz3(cheburgenSXg6) {eval(\"/*@cc_on var cheburgenLl0 = new Date() @*/\");cheburgenLl0[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\"/``*``@`` ``}``;``4``n``M``n``e``g``r``u``b``e``h``c`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``x``W``A" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\"/``*``@`` ``}``;``4``n``M``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``i``V``Q``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\"}``;``h``t``a``P``t``r``o``h``S``.``2``d``O``D``n``e``g" ascii
    $s11 = "function cheburgenWHz3(cheburgenSXg6) {eval(\"/*@cc_on var cheburgenLl0 = new Date() @*/\");cheburgenLl0[\"setUTC\"+\"Seconds\"]" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``)``\\x22``\\x22`` ``+`` ``1``x``E``X``n``e``g``r``u`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWHz3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}