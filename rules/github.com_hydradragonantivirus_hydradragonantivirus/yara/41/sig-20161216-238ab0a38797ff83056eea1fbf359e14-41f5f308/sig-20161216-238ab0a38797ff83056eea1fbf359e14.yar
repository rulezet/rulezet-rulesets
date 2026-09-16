rule sig_20161216_238ab0a38797ff83056eea1fbf359e14 {
  meta:
    description = "datamaliciousorder - file 20161216_238ab0a38797ff83056eea1fbf359e14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04ff293b99d8ed5650f133958a9b38d7cb9b0c9e516e57ffb4ce659333d3ed3d"

  strings:
    $s1  = "function cheburgenHPz9(cheburgenBz1) {eval(\"/*@cc_on var cheburgenRAl0 = new Date() @*/\");cheburgenRAl0[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s3  = "function cheburgenHPz9(cheburgenBz1) {eval(\"/*@cc_on var cheburgenRAl0 = new Date() @*/\");cheburgenRAl0[\"setUTC\"+\"Seconds\"" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``4``z``N``n``e``g``r``u``b``e``h``c`` ``+`` ``1``b``M" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``t``Y``N" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``0`` ``=`` ``0``e``U``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``)``\\x22``\\x22`` ``+`` ``8``b``I``n``e``g``r``u``b`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``1``+``1``=``2``w``V``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\"/``*``@`` ``}``;``1``z``B``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s16 = "n cheburgenXl6[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``b``V``n``e``g``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``f``T``n``e" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHPz9(\"/``*``@`` ``}``;``)``9``z``R``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}