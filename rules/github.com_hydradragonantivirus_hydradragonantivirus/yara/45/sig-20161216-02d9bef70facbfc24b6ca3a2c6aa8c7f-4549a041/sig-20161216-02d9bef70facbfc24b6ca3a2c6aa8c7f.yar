rule sig_20161216_02d9bef70facbfc24b6ca3a2c6aa8c7f {
  meta:
    description = "datamaliciousorder - file 20161216_02d9bef70facbfc24b6ca3a2c6aa8c7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9647475570560c96b60306dadab06ebdabba8e30e59cfdbf035b616e905e1fba"

  strings:
    $s1  = "function cheburgenZCj1(cheburgenDh3) {eval(\"/*@cc_on var cheburgenEWw8 = new Date() @*/\");cheburgenEWw8[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\"/``*``@`` ``}``;``3``h``D``n``e``g``r``u``b``e``h``c`` " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``l``I``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``i``O``X``n" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``)``\\x22``\\x22`` ``+`` ``3``i``X``n``e``g``r``u``b`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\"\")), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``)``\\x22``\\x22`` ``+`` ``3``i``X``n``e``g``r``u``b`" ascii
    $s13 = "rn cheburgenWOf3[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``0`` ``=`` ``4``y``O``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\"/``*``@`` ``}``;``7``r``G``M``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``h``T``n``e``g``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\"/``*``@`` ``}``;``3``f``O``W``n``e``g``r``u``b``e``h``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\";``1``+``1``=``2``o``L``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZCj1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``h``T``n``e``g``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}