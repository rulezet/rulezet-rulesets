rule sig_20161215_4ed094cb72f01a621d00d3a5193d4a95 {
  meta:
    description = "datamaliciousorder - file 20161215_4ed094cb72f01a621d00d3a5193d4a95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af3854792a9d5ae579d59ceffba602d5458ab46a03c29b367950064989a84167"

  strings:
    $s1  = "function cheburgenNCo0(cheburgenCu5) {eval(\"/*@cc_on var cheburgenGo0 = new Date() @*/\");cheburgenGo0[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenGo0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenHo9 = cheburgenCu5[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\"/``*``@`` ``}``;``5``u``C``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``\\x22``i``t``v``j``a``7``a``b``l``/``m``o``c``.``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s9  = "function cheburgenNCo0(cheburgenCu5) {eval(\"/*@cc_on var cheburgenGo0 = new Date() @*/\");cheburgenGo0[\"setUTC\"+\"Seconds\"](" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``r``A``P``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``\\x22``i``t``v``j``a``7``a``b``l``/``m``o``c``.``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``\\x22``p``e``t``f``1``e``8``u``o``/``t``i``.``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\"/``*``@`` ``}``;``2``u``V``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``b``I``n" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``\\x22``\\x22`` ``+`` ``5``z``H``n``e``g``r``u``b`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``r``A``P``n" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNCo0(\"/``*``@`` ``}``;``2``u``V``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}