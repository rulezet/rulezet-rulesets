rule sig_20161215_202213a65f3ce65adf6fe16c844e7497 {
  meta:
    description = "datamaliciousorder - file 20161215_202213a65f3ce65adf6fe16c844e7497.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a192f7378003d0eea4ab08f127021297dd4eb7f428c8375a312269bcbe43825"

  strings:
    $s1  = "function cheburgenJd4(cheburgenGFl7) {eval(\"/*@cc_on var cheburgenWn8 = new Date() @*/\");cheburgenWn8[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenWn8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenYGw5 = cheburgenGFl7[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``." ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\"/``*``@`` ``}``;``4``s``B``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\"}``;``h``t``a``P``t``r``o``h``S``.``5``r``Q``n``e``g``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``s" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = " cheburgenYGw5[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``0`` ``=`` ``4``r``M``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``)``\\x22``\\x22`` ``+`` ``5``o``W``n``e``g``r``u``b``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\"/``*``@`` ``}``;``7``l``F``G``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``k" ascii
    $s17 = "function cheburgenJd4(cheburgenGFl7) {eval(\"/*@cc_on var cheburgenWn8 = new Date() @*/\");cheburgenWn8[\"setUTC\"+\"Seconds\"](" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJd4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}