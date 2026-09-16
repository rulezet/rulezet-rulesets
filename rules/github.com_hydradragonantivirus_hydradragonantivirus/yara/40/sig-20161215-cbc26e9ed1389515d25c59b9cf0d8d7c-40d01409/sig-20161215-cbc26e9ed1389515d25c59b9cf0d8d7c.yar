rule sig_20161215_cbc26e9ed1389515d25c59b9cf0d8d7c {
  meta:
    description = "datamaliciousorder - file 20161215_cbc26e9ed1389515d25c59b9cf0d8d7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f262270402081273ea534ab660a8176033f0d2e5ccb1a1f3aa0312bfd68bc6cb"

  strings:
    $s1  = "function cheburgenXYc4(cheburgenVn0) {eval(\"/*@cc_on var cheburgenHWl7 = new Date() @*/\");cheburgenHWl7[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``9``h``S``n``e``g``r``u``b``e``h``c`` ``+`` ``4``x``S" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\"/``*``@`` ``}``;``0``n``V``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\"/``*``@`` ``}``;``)``3``v``Q``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``v``Y``n``e" ascii
    $s12 = "function cheburgenXYc4(cheburgenVn0) {eval(\"/*@cc_on var cheburgenHWl7 = new Date() @*/\");cheburgenHWl7[\"setUTC\"+\"Seconds\"" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\"/``*``@`` ``}``;``)``3``v``Q``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``0`` ``=`` ``6``h``N``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXYc4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``o``P``H" ascii
    $s20 = "rn cheburgenWYh0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}