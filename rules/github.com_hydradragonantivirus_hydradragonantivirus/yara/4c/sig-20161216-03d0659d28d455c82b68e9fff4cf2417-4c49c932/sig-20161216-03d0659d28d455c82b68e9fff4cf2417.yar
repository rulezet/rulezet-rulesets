rule sig_20161216_03d0659d28d455c82b68e9fff4cf2417 {
  meta:
    description = "datamaliciousorder - file 20161216_03d0659d28d455c82b68e9fff4cf2417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3abd250e2b7209156e59f10d802053c16f4f00488083b25826db28f9fe198174"

  strings:
    $s1  = "function cheburgenAk2(cheburgenLc4) {eval(\"/*@cc_on var cheburgenGMp0 = new Date() @*/\");cheburgenGMp0[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s3  = "function cheburgenAk2(cheburgenLc4) {eval(\"/*@cc_on var cheburgenGMp0 = new Date() @*/\");cheburgenGMp0[\"setUTC\"+\"Seconds\"]" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``t" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\"}``;``h``t``a``P``t``r``o``h``S``.``0``u``L``n``e``g``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``)``\\x22``6``g``c``g``6``/``e``d``.``c``i``s``u``m``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``d``F``n``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``1``h``T``N``n``e``g``r``u``b``e``h``c`` ``+`` ``0``q`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``0`` ``=`` ``4``q``Q``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``1``+``1``=``8``m``V``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\"/``*``@`` ``}``;``2``z``E``F``n``e``g``r``u``b``e``h``c`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``0`` ``=`` ``4``q``Q``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\"/``*``@`` ``}``;``)``7``i``D``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``)``\\x22``\\x22`` ``+`` ``0``k``G``n``e``g``r``u``b``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAk2(\";``1``h``T``N``n``e``g``r``u``b``e``h``c`` ``+`` ``0``q`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}