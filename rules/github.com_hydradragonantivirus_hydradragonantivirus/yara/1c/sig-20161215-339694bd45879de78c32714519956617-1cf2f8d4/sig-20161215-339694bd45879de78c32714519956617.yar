rule sig_20161215_339694bd45879de78c32714519956617 {
  meta:
    description = "datamaliciousorder - file 20161215_339694bd45879de78c32714519956617.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47b2bf0df25fd52132d4ea98917c9ad929fff09138b2f15afb39bfdedc239dff"

  strings:
    $s1  = "function cheburgenKOn9(cheburgenJn3) {eval(\"/*@cc_on var cheburgenWy1 = new Date() @*/\");cheburgenWy1[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenWy1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenEDj0 = cheburgenJn3[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\"}``;``h``t``a``P``t``r``o``h``S``.``5``u``N``Q``n``e``g" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``)``\\x22``\\x22`` ``+`` ``7``r``R``D``n``e``g``r``u`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\"/``*``@`` ``}``;``3``n``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``p``I``Y" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\"/``*``@`` ``}``;``7``z``X``K``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "function cheburgenKOn9(cheburgenJn3) {eval(\"/*@cc_on var cheburgenWy1 = new Date() @*/\");cheburgenWy1[\"setUTC\"+\"Seconds\"](" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``p``I``Y" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``)``\\x22``\\x22`` ``+`` ``7``r``R``D``n``e``g``r``u`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\"/``*``@`` ``}``;``3``n``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\"/``*``@`` ``}``;``0``j``D``E``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenKOn9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``t``D``n``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}