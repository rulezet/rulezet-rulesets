rule sig_20161215_ade3d63489c438164d5a986524ab02bb {
  meta:
    description = "datamaliciousorder - file 20161215_ade3d63489c438164d5a986524ab02bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d5597510462d376b9bc5e42bc2dba527b96ef6c11ae51b5797b7100152e3dc6"

  strings:
    $s1  = "function cheburgenNTa8(cheburgenPc4) {eval(\"/*@cc_on var cheburgenLy5 = new Date() @*/\");cheburgenLy5[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenLy5[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenXo2 = cheburgenPc4[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``)``\\x22``\\x22`` ``+`` ``1``n``A``n``e``g``r``u``b`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\"/``*``@`` ``}``;``)``9``r``E``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``u``B``n``e" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\"/``*``@`` ``}``;``4``c``P``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\"/``*``@`` ``}``;``)``9``r``E``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\"}``;``h``t``a``P``t``r``o``h``S``.``9``a``F``n``e``g``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``1``+``1``=``4``k``Y``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``0`` ``=`` ``5``i``Z``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\"\")), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNTa8(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``" ascii
    $s20 = "heburgenXo2[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}