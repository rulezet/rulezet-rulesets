rule sig_20161216_788ad6c07699cff4b474dd303dacc8d6 {
  meta:
    description = "datamaliciousorder - file 20161216_788ad6c07699cff4b474dd303dacc8d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "972ada634c69dca43e1af4cbbbdb3e6320150dfd9426a154c84a8005125678d6"

  strings:
    $s1  = "\"20\");if (cheburgenMd7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenMj1 = cheburgenVIb6[\"split\"](\"`" ascii
    $s2  = "function cheburgenGZh9(cheburgenVIb6) {eval(\"/*@cc_on var cheburgenMd7 = new Date() @*/\");cheburgenMd7[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``)``\\x22``\\x22`` ``+`` ``4``w``X``n``e``g``r``u``b`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s5  = "function cheburgenGZh9(cheburgenVIb6) {eval(\"/*@cc_on var cheburgenMd7 = new Date() @*/\");cheburgenMd7[\"setUTC\"+\"Seconds\"]" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``)``\\x22``m``e``k``k``8``u``o``/``m``o``c``.``s``n``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\"/``*``@`` ``}``;``5``m``I``M``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\"/``*``@`` ``}``;``)``9``m``Q``n``e``g``r``u``b``e``h``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``0`` ``=`` ``7``z``C``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\"/``*``@`` ``}``;``6``b``I``V``n``e``g``r``u``b``e``h``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``)``\\x22``p``e``t``f``1``e``8``u``o``/``t``i``.``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\"}``;``h``t``a``P``t``r``o``h``S``.``8``x``P``n``e``g``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\"}``;``h``t``a``P``t``r``o``h``S``.``8``x``P``n``e``g``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGZh9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}