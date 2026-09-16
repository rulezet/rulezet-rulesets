rule sig_20161216_0791d45aa23f8e2d8d84b92a6090a98b {
  meta:
    description = "datamaliciousorder - file 20161216_0791d45aa23f8e2d8d84b92a6090a98b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "714159c9116126ded429e53bca042e3c8b8f6b86f3f2d945081c1cc9e66cc991"

  strings:
    $s1  = "20\");if (cheburgenZb1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenVNq3 = cheburgenOx0[\"split\"](\"``" ascii
    $s2  = "function cheburgenIGe9(cheburgenOx0) {eval(\"/*@cc_on var cheburgenZb1 = new Date() @*/\");cheburgenZb1[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``)``\\x22``i``e``x``w``w``r``m``a``/``m``o``c``.``h``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\"/``*``@`` ``}``;``3``m``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "function cheburgenIGe9(cheburgenOx0) {eval(\"/*@cc_on var cheburgenZb1 = new Date() @*/\");cheburgenZb1[\"setUTC\"+\"Seconds\"](" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\"}``;``h``t``a``P``t``r``o``h``S``.``6``k``J``n``e``g``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``)``\\x22``\\x22`` ``+`` ``6``e``T``n``e``g``r``u``b`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``a``S``T" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\"/``*``@`` ``}``;``0``x``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``1``+``1``=``8``m``X``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\"/``*``@`` ``}``;``3``m``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``q``J``n``e" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIGe9(\";``0`` ``=`` ``5``e``G``n``e``g``r``u``b``e``h``c`` ``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}