rule sig_20161216_65be7a2d60b409530a90d20124a9b35f {
  meta:
    description = "datamaliciousorder - file 20161216_65be7a2d60b409530a90d20124a9b35f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b87976c7d10b49177b4ad275ae23c0612dbf73f289346e79dce6a9b03459ac5c"

  strings:
    $s1  = "function cheburgenDk6(cheburgenCg9) {eval(\"/*@cc_on var cheburgenXj9 = new Date() @*/\");cheburgenXj9[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenXj9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenAt2 = cheburgenCg9[\"split\"](\"``\")" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``i``O``H`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\"}``;``h``t``a``P``t``r``o``h``S``.``7``c``C``A``n``e``g`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``)``\\x22``\\x22`` ``+`` ``1``e``E``n``e``g``r``u``b``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``w" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\"/``*``@`` ``}``;``2``t``A``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\"/``*``@`` ``}``;``)``7``b``C``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\"/``*``@`` ``}``;``1``p``E``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "function cheburgenDk6(cheburgenCg9) {eval(\"/*@cc_on var cheburgenXj9 = new Date() @*/\");cheburgenXj9[\"setUTC\"+\"Seconds\"](" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDk6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}