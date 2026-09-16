rule sig_20161216_180fac0ac6ce59235a8801a591c9ee4b {
  meta:
    description = "datamaliciousorder - file 20161216_180fac0ac6ce59235a8801a591c9ee4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01fccebbf273f25da089b723805cb4eb18a5f8528ac6e4198d6e412f007df0d2"

  strings:
    $s1  = "0\");if (cheburgenCz2[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenVUc0 = cheburgenFe2[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenKa7(cheburgenFe2) {eval(\"/*@cc_on var cheburgenCz2 = new Date() @*/\");cheburgenCz2[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``0`` ``=`` ``4``g``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\"/``*``@`` ``}``;``)``2``d``V``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``5``w``W``n``e``g``r``u``b``e``h``c`` ``+`` ``6``r``H`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``h``Y``K``n`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``1``+``1``=``7``m``X``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\"/``*``@`` ``}``;``3``k``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``)``\\x22``d``o``9``u``h``q``s``f``3``a``/``w``z``.``g" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``0`` ``=`` ``4``g``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``s``O``n`" ascii
    $s13 = "heburgenVUc0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\"}``;``h``t``a``P``t``r``o``h``S``.``4``z``X``Z``n``e``g`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\"/``*``@`` ``}``;``)``2``d``V``n``e``g``r``u``b``e``h``c`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKa7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}