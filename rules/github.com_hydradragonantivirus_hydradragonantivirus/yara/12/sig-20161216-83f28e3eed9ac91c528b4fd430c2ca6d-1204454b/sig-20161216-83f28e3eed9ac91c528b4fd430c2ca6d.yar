rule sig_20161216_83f28e3eed9ac91c528b4fd430c2ca6d {
  meta:
    description = "datamaliciousorder - file 20161216_83f28e3eed9ac91c528b4fd430c2ca6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13bbeb3f30cbc7bd6082659c0451b6b75f53accaa1173c15145694628498af01"

  strings:
    $s1  = "function cheburgenGu6(cheburgenEv0) {eval(\"/*@cc_on var cheburgenLXa1 = new Date() @*/\");cheburgenLXa1[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``6``u``V``n``e``g``r``u``b``e``h``c`` ``+`` ``6``m``T`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``1``+``1``=``5``g``A``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"/``*``@`` ``}``;``4``h``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"/``*``@`` ``}``;``4``h``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``a" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"}``;``h``t``a``P``t``r``o``h``S``.``1``j``R``M``n``e``g`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"}``;``h``t``a``P``t``r``o``h``S``.``1``j``R``M``n``e``g`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"/``*``@`` ``}``;``0``y``P``P``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``f``J``n`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\";``)``\\x22``p``m``h``k``t``e``z``0``/``o``f``n``i``.``e" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGu6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}