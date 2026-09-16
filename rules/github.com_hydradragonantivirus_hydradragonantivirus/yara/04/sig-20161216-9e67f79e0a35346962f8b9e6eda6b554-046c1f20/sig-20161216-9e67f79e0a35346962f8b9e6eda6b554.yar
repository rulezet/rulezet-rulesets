rule sig_20161216_9e67f79e0a35346962f8b9e6eda6b554 {
  meta:
    description = "datamaliciousorder - file 20161216_9e67f79e0a35346962f8b9e6eda6b554.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8946166bca493b5cb340597ceb69c654e73001222545976c26ea510156774e10"

  strings:
    $s1  = "function cheburgenTf2(cheburgenUs6) {eval(\"/*@cc_on var cheburgenBDq1 = new Date() @*/\");cheburgenBDq1[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``0`` ``=`` ``6``j``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``a``I``N``n`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\"/``*``@`` ``}``;``1``v``G``B``n``e``g``r``u``b``e``h``c`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``-" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\"/``*``@`` ``}``;``1``v``G``B``n``e``g``r``u``b``e``h``c`" ascii
    $s13 = "n cheburgenGWv9[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``1``+``1``=``5``z``C``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``1``+``1``=``5``z``C``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``0`` ``=`` ``6``j``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\"/``*``@`` ``}``;``9``v``W``G``n``e``g``r``u``b``e``h``c`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTf2(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``d" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}