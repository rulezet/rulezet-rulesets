rule sig_20161215_912370d9cedff6a7ff3010ed4aab952d {
  meta:
    description = "datamaliciousorder - file 20161215_912370d9cedff6a7ff3010ed4aab952d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4e8e0d4c708c32d3c67e1e135a30fc13c89966a30ff2b9ddb39ec51112fa27e"

  strings:
    $s1  = "function cheburgenQFm2(cheburgenVFj7) {eval(\"/*@cc_on var cheburgenFWt7 = new Date() @*/\");cheburgenFWt7[\"setUTC\"+\"Seconds" ascii
    $s2  = "function cheburgenQFm2(cheburgenVFj7) {eval(\"/*@cc_on var cheburgenFWt7 = new Date() @*/\");cheburgenFWt7[\"setUTC\"+\"Seconds" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``0`` ``=`` ``4``i``W``R``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``j``U``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``1``+``1``=``4``q``W``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\"}``;``h``t``a``P``t``r``o``h``S``.``1``o``I``A``n``e``g" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\"/``*``@`` ``}``;``5``r``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\"\")), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``7``l``O``V``n``e``g``r``u``b``e``h``c`` ``+`` ``0``l" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQFm2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}