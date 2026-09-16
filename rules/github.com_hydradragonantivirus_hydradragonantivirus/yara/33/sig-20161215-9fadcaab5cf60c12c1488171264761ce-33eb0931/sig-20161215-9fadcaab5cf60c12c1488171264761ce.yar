rule sig_20161215_9fadcaab5cf60c12c1488171264761ce {
  meta:
    description = "datamaliciousorder - file 20161215_9fadcaab5cf60c12c1488171264761ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a40325cbe2b4939f6d71c3192a5d7f0575b4893e298a293273357c0a41b5e0e"

  strings:
    $s1  = "function cheburgenZd7(cheburgenKIq5) {eval(\"/*@cc_on var cheburgenMIt1 = new Date() @*/\");cheburgenMIt1[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``o" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\"}``;``h``t``a``P``t``r``o``h``S``.``7``y``V``n``e``g``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``)``\\x22``\\x22`` ``+`` ``5``h``E``n``e``g``r``u``b``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``7``g``A``n``e``g``r``u``b``e``h``c`` ``+`` ``8``n``Q`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\"/``*``@`` ``}``;``4``f``F``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``0`` ``=`` ``2``m``X``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``o" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\"/``*``@`` ``}``;``9``d``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``0`` ``=`` ``2``m``X``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``i``F``n`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``i" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZd7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``t``F``n``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}