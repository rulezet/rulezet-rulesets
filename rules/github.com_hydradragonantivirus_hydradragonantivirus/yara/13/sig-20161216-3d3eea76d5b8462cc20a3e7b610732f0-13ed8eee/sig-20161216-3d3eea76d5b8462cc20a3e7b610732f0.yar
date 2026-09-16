rule sig_20161216_3d3eea76d5b8462cc20a3e7b610732f0 {
  meta:
    description = "datamaliciousorder - file 20161216_3d3eea76d5b8462cc20a3e7b610732f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64175404318009b43e8d0fd87cc392eb762887ac2dcf8e7793f4ba02614eb308"

  strings:
    $s1  = "function cheburgenNZg4(cheburgenZYs6) {eval(\"/*@cc_on var cheburgenWLl0 = new Date() @*/\");cheburgenWLl0[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``j``N``n``e" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``7``g``I``Y``n``e``g``r``u``b``e``h``c`` ``+`` ``1``b" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``0`` ``=`` ``8``f``L``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``\\x22``d``g``l``i``l``x``x``a``/``e``d``.``g``n``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``s``J``C" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\"}``;``h``t``a``P``t``r``o``h``S``.``3``a``J``X``n``e``g" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\"/``*``@`` ``}``;``)``1``c``U``n``e``g``r``u``b``e``h``c" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\";``)``\\x22``d``g``l``i``l``x``x``a``/``e``d``.``g``n``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\"/``*``@`` ``}``;``6``s``Y``Z``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNZg4(\"/``*``@`` ``}``;``)``1``c``U``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}