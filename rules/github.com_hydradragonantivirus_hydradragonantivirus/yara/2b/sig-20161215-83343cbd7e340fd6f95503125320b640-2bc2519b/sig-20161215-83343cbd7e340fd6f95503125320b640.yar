rule sig_20161215_83343cbd7e340fd6f95503125320b640 {
  meta:
    description = "datamaliciousorder - file 20161215_83343cbd7e340fd6f95503125320b640.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3235d30947fae7b2106044e6323aa10ebca27bdc484ff452bdfdda6a26ad5dd5"

  strings:
    $s1  = "function cheburgenXl6(cheburgenVk1) {eval(\"/*@cc_on var cheburgenJWf4 = new Date() @*/\");cheburgenJWf4[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenJWf4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenDa8 = cheburgenVk1[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\"/``*``@`` ``}``;``0``b``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``1``+``1``=``1``o``Q``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``1``h``X``O``n``e``g``r``u``b``e``h``c`` ``+`` ``6``k`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\"/``*``@`` ``}``;``8``a``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\"/``*``@`` ``}``;``0``b``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``s``E``n`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``)``\\x22``p``a``h``5``d``d``w``b``c``5``/``m``o``c``." ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``)``\\x22``n``p``u``a``b``u``/``g``r``o``.``e``v``i``t" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\"}``;``h``t``a``P``t``r``o``h``S``.``5``h``M``n``e``g``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``1``h``X``O``n``e``g``r``u``b``e``h``c`` ``+`` ``6``k`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXl6(\";``)``\\x22``\\x22`` ``+`` ``1``u``M``P``n``e``g``r``u``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}