rule sig_20161215_274973e7bb2cb3c2551def46b35c564d {
  meta:
    description = "datamaliciousorder - file 20161215_274973e7bb2cb3c2551def46b35c564d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74524601ee09d57435f0ff39d82ad5f9754429e6be602b0500dc627a31988015"

  strings:
    $s1  = "function cheburgenJc5(cheburgenVg4) {eval(\"/*@cc_on var cheburgenRt3 = new Date() @*/\");cheburgenRt3[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenRt3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenOo0 = cheburgenVg4[\"split\"](\"``\")" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``0`` ``=`` ``2``f``J``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "function cheburgenJc5(cheburgenVg4) {eval(\"/*@cc_on var cheburgenRt3 = new Date() @*/\");cheburgenRt3[\"setUTC\"+\"Seconds\"](" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``)``\\x22``\\x22`` ``+`` ``9``d``Z``n``e``g``r``u``b``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\"/``*``@`` ``}``;``4``g``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\"}``;``h``t``a``P``t``r``o``h``S``.``0``p``G``S``n``e``g`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\"/``*``@`` ``}``;``)``6``r``U``V``n``e``g``r``u``b``e``h`" ascii
    $s14 = "eburgenOo0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\"/``*``@`` ``}``;``0``o``O``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``)``\\x22``d``v``6``u``5``9``i``5``8``/``m``o``c``.``g" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``)``\\x22``d``v``6``u``5``9``i``5``8``/``m``o``c``.``g" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\"/``*``@`` ``}``;``2``m``T``X``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``)``\\x22``y``b``6``g``h``i``9``/``m``o``c``.``n``g``i" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJc5(\";``)``\\x22``d``l``d``s``v``9``/``m``o``c``.``g``n``u``o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}