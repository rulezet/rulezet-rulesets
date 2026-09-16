rule sig_20161216_a460593688bc83a90bd85787e9bf2622 {
  meta:
    description = "datamaliciousorder - file 20161216_a460593688bc83a90bd85787e9bf2622.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1b704ee0612969f3c37c8c9b066ae71c234f6af2176e44f05af73b18812ee26"

  strings:
    $s1  = "function cheburgenELg7(cheburgenBRe5) {eval(\"/*@cc_on var cheburgenNt1 = new Date() @*/\");cheburgenNt1[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\"}``;``h``t``a``P``t``r``o``h``S``.``4``z``A``I``n``e``g" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\"\")), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\"/``*``@`` ``}``;``9``v``V``X``n``e``g``r``u``b``e``h``c" ascii
    $s8  = "n cheburgenXVv9[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\"/``*``@`` ``}``;``)``1``z``O``W``n``e``g``r``u``b``e``h" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\"/``*``@`` ``}``;``5``e``R``B``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``h``B``X" ascii
    $s12 = "function cheburgenELg7(cheburgenBRe5) {eval(\"/*@cc_on var cheburgenNt1 = new Date() @*/\");cheburgenNt1[\"setUTC\"+\"Seconds\"]" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\"/``*``@`` ``}``;``9``v``V``X``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\"/``*``@`` ``}``;``5``e``R``B``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``0`` ``=`` ``3``c``U``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``9``w``B``P``n``e``g``r``u``b``e``h``c`` ``+`` ``1``b" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenELg7(\"/``*``@`` ``}``;``3``v``J``W``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}