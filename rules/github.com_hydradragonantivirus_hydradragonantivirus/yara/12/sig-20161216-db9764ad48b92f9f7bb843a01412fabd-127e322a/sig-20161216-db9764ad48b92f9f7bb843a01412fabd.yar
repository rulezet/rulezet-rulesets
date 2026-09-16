rule sig_20161216_db9764ad48b92f9f7bb843a01412fabd {
  meta:
    description = "datamaliciousorder - file 20161216_db9764ad48b92f9f7bb843a01412fabd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c931f69d60198734fbb7dcbbadb5ebf80b7590bc1c68b5e4539dd204230aefca"

  strings:
    $s1  = "function cheburgenZXx0(cheburgenZDw4) {eval(\"/*@cc_on var cheburgenLSz5 = new Date() @*/\");cheburgenLSz5[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\"/``*``@`` ``}``;``)``5``h``A``G``n``e``g``r``u``b``e``h" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``f``B``M" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\"/``*``@`` ``}``;``3``i``F``I``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\"/``*``@`` ``}``;``)``5``h``A``G``n``e``g``r``u``b``e``h" ascii
    $s15 = "function cheburgenZXx0(cheburgenZDw4) {eval(\"/*@cc_on var cheburgenLSz5 = new Date() @*/\");cheburgenLSz5[\"setUTC\"+\"Seconds" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\"/``*``@`` ``}``;``3``i``F``I``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "turn cheburgenIFi3[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\";``)``\\x22``\\x22`` ``+`` ``1``f``C``n``e``g``r``u``b`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\"/``*``@`` ``}``;``4``w``D``Z``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZXx0(\"/``*``@`` ``}``;``4``w``D``Z``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}