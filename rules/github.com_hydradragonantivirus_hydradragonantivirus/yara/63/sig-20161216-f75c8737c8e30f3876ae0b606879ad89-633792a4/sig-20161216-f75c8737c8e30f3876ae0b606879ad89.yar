rule sig_20161216_f75c8737c8e30f3876ae0b606879ad89 {
  meta:
    description = "datamaliciousorder - file 20161216_f75c8737c8e30f3876ae0b606879ad89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01349d23e31c96436cd8606c49bb828df7a42df17896b12f9e3cfe445643f440"

  strings:
    $s1  = "function cheburgenFa9(cheburgenVk9) {eval(\"/*@cc_on var cheburgenKFn5 = new Date() @*/\");cheburgenKFn5[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``v``D``H`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\"/``*``@`` ``}``;``0``u``N``U``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``0``d``G``U``n``e``g``r``u``b``e``h``c`` ``+`` ``9``w`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "function cheburgenFa9(cheburgenVk9) {eval(\"/*@cc_on var cheburgenKFn5 = new Date() @*/\");cheburgenKFn5[\"setUTC\"+\"Seconds\"]" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\"/``*``@`` ``}``;``0``u``N``U``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``v``D``H`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``g``D``P``n``e``g`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``u``Z``n``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFa9(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}