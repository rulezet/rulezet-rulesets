rule sig_20161215_cbef36fa20f15527180482cf0bfbc286 {
  meta:
    description = "datamaliciousorder - file 20161215_cbef36fa20f15527180482cf0bfbc286.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8c9e8869f8879ac50e2c8cb0f6215748e16a84a41c90fed88f63e93b6d9e4bf"

  strings:
    $s1  = "20\");if (cheburgenVj3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenWh8 = cheburgenPXy8[\"split\"](\"``" ascii
    $s2  = "function cheburgenGm3(cheburgenPXy8) {eval(\"/*@cc_on var cheburgenVj3 = new Date() @*/\");cheburgenVj3[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``0`` ``=`` ``6``r``H``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "function cheburgenGm3(cheburgenPXy8) {eval(\"/*@cc_on var cheburgenVj3 = new Date() @*/\");cheburgenVj3[\"setUTC\"+\"Seconds\"](" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``u" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "cheburgenWh8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``)``\\x22``l``w``m``8``r``t``h``o``p``/``k``d``.``e``v" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``w" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``0``j``K``n``e``g``r``u``b``e``h``c`` ``+`` ``2``x``Q`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\"/``*``@`` ``}``;``8``y``X``P``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\"/``*``@`` ``}``;``8``h``W``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``)``\\x22``\\x22`` ``+`` ``2``z``Z``n``e``g``r``u``b``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``0`` ``=`` ``6``r``H``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``f``P``S`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGm3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``f``P``S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}