rule sig_20161216_95fd52f2b80c8fcd788a6c11c7f318a5 {
  meta:
    description = "datamaliciousorder - file 20161216_95fd52f2b80c8fcd788a6c11c7f318a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46da8ba3c10e9b87cb636606fd3deb3e32908536496543f1354205b9cb35944c"

  strings:
    $s1  = "\"20\");if (cheburgenZv9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenRa6 = cheburgenPLd5[\"split\"](\"`" ascii
    $s2  = "function cheburgenFZi7(cheburgenPLd5) {eval(\"/*@cc_on var cheburgenZv9 = new Date() @*/\");cheburgenZv9[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``6``d``T``n``e``g``r``u``b``e``h``c`` ``+`` ``6``i``W" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``h``N``F``n" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``0`` ``=`` ``9``x``R``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\"/``*``@`` ``}``;``4``m``Q``B``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\"/``*``@`` ``}``;``5``d``L``P``n``e``g``r``u``b``e``h``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``)``\\x22``p``a``h``5``d``d``w``b``c``5``/``m``o``c``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``0`` ``=`` ``9``x``R``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\"/``*``@`` ``}``;``)``6``r``I``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``h``N``F``n" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\";``)``\\x22``\\x22`` ``+`` ``4``m``S``A``n``e``g``r``u`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFZi7(\"/``*``@`` ``}``;``4``m``Q``B``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}