rule sig_20161216_30314929737a76ce352a9a2f04511383 {
  meta:
    description = "datamaliciousorder - file 20161216_30314929737a76ce352a9a2f04511383.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e161ef1ef76b8c7d3023ad09e0b13cd48be5838f476510738a837dee61ded072"

  strings:
    $s1  = "0\");if (cheburgenRi2[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenRHt7 = cheburgenDi8[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenNg0(cheburgenDi8) {eval(\"/*@cc_on var cheburgenRi2 = new Date() @*/\");cheburgenRi2[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\";``1``+``1``=``9``v``L``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s4  = "function cheburgenNg0(cheburgenDi8) {eval(\"/*@cc_on var cheburgenRi2 = new Date() @*/\");cheburgenRi2[\"setUTC\"+\"Seconds\"](" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\"/``*``@`` ``}``;``8``i``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\"/``*``@`` ``}``;``)``9``z``M``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\"/``*``@`` ``}``;``3``z``L``P``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\"}``;``h``t``a``P``t``r``o``h``S``.``2``z``O``n``e``g``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``e``R``n``e`" ascii
    $s12 = "heburgenRHt7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``i" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\"/``*``@`` ``}``;``8``i``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\"/``*``@`` ``}``;``)``9``z``M``n``e``g``r``u``b``e``h``c`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``y" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNg0(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``." ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}