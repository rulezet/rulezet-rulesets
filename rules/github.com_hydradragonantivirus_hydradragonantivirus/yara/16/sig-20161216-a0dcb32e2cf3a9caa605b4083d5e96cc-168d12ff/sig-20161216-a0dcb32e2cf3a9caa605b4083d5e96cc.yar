rule sig_20161216_a0dcb32e2cf3a9caa605b4083d5e96cc {
  meta:
    description = "datamaliciousorder - file 20161216_a0dcb32e2cf3a9caa605b4083d5e96cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f5a6dcf2cb29f5a75072d24eac1070225f5ac74ab7b97a7214a1f6380361e93"

  strings:
    $s1  = "function cheburgenUn1(cheburgenOXi0) {eval(\"/*@cc_on var cheburgenLMl4 = new Date() @*/\");cheburgenLMl4[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\"/``*``@`` ``}``;``)``7``f``R``n``e``g``r``u``b``e``h``c`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``1``+``1``=``9``m``Z``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``)``\\x22``i``e``x``w``w``r``m``a``/``m``o``c``.``h``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "function cheburgenUn1(cheburgenOXi0) {eval(\"/*@cc_on var cheburgenLMl4 = new Date() @*/\");cheburgenLMl4[\"setUTC\"+\"Seconds\"" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\"/``*``@`` ``}``;``8``z``Y``P``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\"/``*``@`` ``}``;``1``b``A``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``0`` ``=`` ``9``r``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\"}``;``h``t``a``P``t``r``o``h``S``.``5``s``N``n``e``g``r`" ascii
    $s15 = "urn cheburgenPYz8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\"\")), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUn1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}