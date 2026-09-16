rule sig_20161215_8112d6637e4e67bdad2f2c983f7b279e {
  meta:
    description = "datamaliciousorder - file 20161215_8112d6637e4e67bdad2f2c983f7b279e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9462f559b44f4296dba936e88fbabd1713c4b96d571c333f1214504d91185dde"

  strings:
    $s1  = "function cheburgenYv6(cheburgenCz8) {eval(\"/*@cc_on var cheburgenKGl2 = new Date() @*/\");cheburgenKGl2[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\"/``*``@`` ``}``;``8``z``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``0`` ``=`` ``0``e``T``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\"}``;``h``t``a``P``t``r``o``h``S``.``5``q``T``n``e``g``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``p``Y``W``n`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``)``\\x22``n``p``u``a``b``u``/``g``r``o``.``e``v``i``t" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\"/``*``@`` ``}``;``)``4``r``B``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\"/``*``@`` ``}``;``5``w``H``B``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``s" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``)``\\x22``n``p``u``a``b``u``/``g``r``o``.``e``v``i``t" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``p``Y``W``n`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``1``+``1``=``8``t``J``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYv6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "function cheburgenYv6(cheburgenCz8) {eval(\"/*@cc_on var cheburgenKGl2 = new Date() @*/\");cheburgenKGl2[\"setUTC\"+\"Seconds\"]" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}