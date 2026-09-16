rule sig_20161215_09beec64630b14c684afe34b0e5b0d8f {
  meta:
    description = "datamaliciousorder - file 20161215_09beec64630b14c684afe34b0e5b0d8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "520b5955a60c91ee66ee8fee10b89e8f1a2c99f4def5aec46a9d89aa0ba2df47"

  strings:
    $s1  = "function cheburgenVTj5(cheburgenXz0) {eval(\"/*@cc_on var cheburgenUVn8 = new Date() @*/\");cheburgenUVn8[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``7``s``K``L``n``e``g``r``u``b``e``h``c`` ``+`` ``4``f" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``i``G``E" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``1``+``1``=``8``u``N``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\"}``;``h``t``a``P``t``r``o``h``S``.``1``e``R``S``n``e``g" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``)``\\x22``\\x22`` ``+`` ``7``g``Y``n``e``g``r``u``b`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``)``\\x22``d``l``d``s``v``9``/``m``o``c``.``g``n``u``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\"/``*``@`` ``}``;``1``y``P``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\"/``*``@`` ``}``;``1``y``P``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\"/``*``@`` ``}``;``)``7``q``J``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "function cheburgenVTj5(cheburgenXz0) {eval(\"/*@cc_on var cheburgenUVn8 = new Date() @*/\");cheburgenUVn8[\"setUTC\"+\"Seconds\"" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``0`` ``=`` ``5``g``K``E``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\"/``*``@`` ``}``;``0``z``X``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``i``G``E" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVTj5(\"}``;``h``t``a``P``t``r``o``h``S``.``1``e``R``S``n``e``g" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}