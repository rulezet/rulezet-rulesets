rule sig_20161216_b314876ef7ff1d8b1f4d31d0905e061a {
  meta:
    description = "datamaliciousorder - file 20161216_b314876ef7ff1d8b1f4d31d0905e061a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a02e0f8c81b1c5da97c019dd2a72e818b575166a201805ecf0975f7ea9a7539d"

  strings:
    $s1  = "function cheburgenYc2(cheburgenEQi6) {eval(\"/*@cc_on var cheburgenZHf0 = new Date() @*/\");cheburgenZHf0[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``\\x22``g``c``w``h``p``/``a``u``.``m``o``c``.``z``a" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``\\x22``g``9``t``o``f``a``p``n``p``/``m``o``c``.``s" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\"/``*``@`` ``}``;``6``i``Q``E``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``\\x22``\\x22`` ``+`` ``1``b``X``G``n``e``g``r``u``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``6``v``D``Z``n``e``g``r``u``b``e``h``c`` ``+`` ``0``n`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``6``v``D``Z``n``e``g``r``u``b``e``h``c`` ``+`` ``0``n`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``l``I``N`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\"/``*``@`` ``}``;``3``s``O``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``\\x22``g``9``t``o``f``a``p``n``p``/``m``o``c``.``s" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``o``J``n``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``\\x22``g``c``w``h``p``/``a``u``.``m``o``c``.``z``a" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\"}``;``h``t``a``P``t``r``o``h``S``.``5``x``Y``n``e``g``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYc2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}