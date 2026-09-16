rule sig_20161216_5280db40cb17f31b983ad46111c17543 {
  meta:
    description = "datamaliciousorder - file 20161216_5280db40cb17f31b983ad46111c17543.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8efb99d32a901ee8e32b365524ca73f6d00cbdb4b34c8097d6c3a93bd888f4d7"

  strings:
    $s1  = "function cheburgenXg5(cheburgenCPc7) {eval(\"/*@cc_on var cheburgenFTj0 = new Date() @*/\");cheburgenFTj0[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\"/``*``@`` ``}``;``8``q``S``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``)``\\x22``\\x22`` ``+`` ``7``c``J``K``n``e``g``r``u``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``a" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\"/``*``@`` ``}``;``6``k``G``P``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "function cheburgenXg5(cheburgenCPc7) {eval(\"/*@cc_on var cheburgenFTj0 = new Date() @*/\");cheburgenFTj0[\"setUTC\"+\"Seconds\"" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\"/``*``@`` ``}``;``7``c``P``C``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``0`` ``=`` ``0``j``E``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``a" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\"/``*``@`` ``}``;``8``q``S``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``1``+``1``=``7``f``P``N``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\"/``*``@`` ``}``;``7``c``P``C``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``4``f``Y``O``n``e``g``r``u``b``e``h``c`` ``+`` ``1``o`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXg5(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}