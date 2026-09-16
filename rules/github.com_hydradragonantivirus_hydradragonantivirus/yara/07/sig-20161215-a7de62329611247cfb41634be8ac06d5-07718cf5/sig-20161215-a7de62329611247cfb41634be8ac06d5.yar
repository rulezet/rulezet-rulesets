rule sig_20161215_a7de62329611247cfb41634be8ac06d5 {
  meta:
    description = "datamaliciousorder - file 20161215_a7de62329611247cfb41634be8ac06d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cbbf5cb0fe9f62ee4f2144e85f565c4c98bbeefd108afd5314a76990a6e42c1"

  strings:
    $s1  = "function cheburgenIo4(cheburgenIj2) {eval(\"/*@cc_on var cheburgenNCl1 = new Date() @*/\");cheburgenNCl1[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``c``Q``n``e`" ascii
    $s3  = "n cheburgenEGy8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\"}``;``h``t``a``P``t``r``o``h``S``.``0``g``T``n``e``g``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``-" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``)``\\x22``d``q``j``4``d``u``/``m``o``c``.``d``n``a``l" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``-" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\"/``*``@`` ``}``;``8``y``G``E``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``)``\\x22``\\x22`` ``+`` ``2``o``Q``H``n``e``g``r``u``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s16 = "function cheburgenIo4(cheburgenIj2) {eval(\"/*@cc_on var cheburgenNCl1 = new Date() @*/\");cheburgenNCl1[\"setUTC\"+\"Seconds\"]" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\"/``*``@`` ``}``;``)``6``m``O``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``1``+``1``=``5``y``Z``S``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``6``g``F``D``n``e``g``r``u``b``e``h``c`` ``+`` ``6``u`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo4(\";``)``\\x22``d``q``j``4``d``u``/``m``o``c``.``d``n``a``l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}