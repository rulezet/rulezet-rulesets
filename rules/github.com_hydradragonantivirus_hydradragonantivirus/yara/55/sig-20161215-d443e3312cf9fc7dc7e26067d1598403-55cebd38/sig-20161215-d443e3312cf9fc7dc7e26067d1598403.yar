rule sig_20161215_d443e3312cf9fc7dc7e26067d1598403 {
  meta:
    description = "datamaliciousorder - file 20161215_d443e3312cf9fc7dc7e26067d1598403.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c064fb289ecda2416943d77736cb001a33301d84f8782305bf42cfcea4b7641c"

  strings:
    $s1  = "function cheburgenLZe7(cheburgenUy7) {eval(\"/*@cc_on var cheburgenNYn8 = new Date() @*/\");cheburgenNYn8[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``z``D``Y" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``z``I``n``e" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\"/``*``@`` ``}``;``7``y``U``n``e``g``r``u``b``e``h``c`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``z``I``n``e" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``9``i``M``n``e``g``r``u``b``e``h``c`` ``+`` ``7``r``V" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\"\")), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\"/``*``@`` ``}``;``8``y``G``E``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``\\x22``\\x22`` ``+`` ``5``p``U``n``e``g``r``u``b`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``\\x22``c``g``r``n``t``c``4``q``q``/``m``o``c``.``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``)``\\x22``\\x22`` ``+`` ``5``p``U``n``e``g``r``u``b`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``1``+``1``=``2``z``R``Z``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLZe7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}