rule sig_20161216_0f62ca792b43bd3d67a3a260a00d0d43 {
  meta:
    description = "datamaliciousorder - file 20161216_0f62ca792b43bd3d67a3a260a00d0d43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "371489d4a42678f162fa65d726cca3af2b860ffbe0a21bc597dea19ddd3649e3"

  strings:
    $s1  = "function cheburgenQy2(cheburgenWZr4) {eval(\"/*@cc_on var cheburgenDr4 = new Date() @*/\");cheburgenDr4[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenDr4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenKLc0 = cheburgenWZr4[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``u``Q``n`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``a" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``)``\\x22``\\x22`` ``+`` ``6``e``Y``n``e``g``r``u``b``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\"}``;``h``t``a``P``t``r``o``h``S``.``6``j``N``Z``n``e``g`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\"/``*``@`` ``}``;``)``1``n``Q``C``n``e``g``r``u``b``e``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``g``H``W``n`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\"/``*``@`` ``}``;``0``c``L``K``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``)``\\x22``p``e``t``f``1``e``8``u``o``/``t``i``.``l``o" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``5``x``M``D``n``e``g``r``u``b``e``h``c`` ``+`` ``4``k`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = " cheburgenKLc0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQy2(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}