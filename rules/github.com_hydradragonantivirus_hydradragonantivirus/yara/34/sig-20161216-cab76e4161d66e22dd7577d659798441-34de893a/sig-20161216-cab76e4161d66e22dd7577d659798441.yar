rule sig_20161216_cab76e4161d66e22dd7577d659798441 {
  meta:
    description = "datamaliciousorder - file 20161216_cab76e4161d66e22dd7577d659798441.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1486aa10e836875039579474081f4b856e2eea7512dc3dded7b3921d37fcdd3"

  strings:
    $s1  = "function cheburgenEQm6(cheburgenNr8) {eval(\"/*@cc_on var cheburgenCz5 = new Date() @*/\");cheburgenCz5[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenCz5[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenOb5 = cheburgenNr8[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\"}``;``h``t``a``P``t``r``o``h``S``.``9``f``Z``n``e``g``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``)``\\x22``\\x22`` ``+`` ``8``d``K``n``e``g``r``u``b`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\"/``*``@`` ``}``;``5``b``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\"/``*``@`` ``}``;``5``j``Z``D``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "function cheburgenEQm6(cheburgenNr8) {eval(\"/*@cc_on var cheburgenCz5 = new Date() @*/\");cheburgenCz5[\"setUTC\"+\"Seconds\"](" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\"\")), 1);//////////////////////////////////////////////" ascii
    $s13 = "heburgenOb5[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``0`` ``=`` ``5``s``G``L``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\"/``*``@`` ``}``;``5``b``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\"/``*``@`` ``}``;``)``1``a``X``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\"}``;``h``t``a``P``t``r``o``h``S``.``9``f``Z``n``e``g``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEQm6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``b``P``C" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}