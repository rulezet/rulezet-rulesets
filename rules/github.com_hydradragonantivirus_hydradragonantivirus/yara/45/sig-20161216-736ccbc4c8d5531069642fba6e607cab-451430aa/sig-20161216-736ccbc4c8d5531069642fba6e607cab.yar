rule sig_20161216_736ccbc4c8d5531069642fba6e607cab {
  meta:
    description = "datamaliciousorder - file 20161216_736ccbc4c8d5531069642fba6e607cab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74eee61c3315d7057315be2775bd0ca2289ec67564790bc2fb6731c4aaeb9f6b"

  strings:
    $s1  = "function cheburgenZy5(cheburgenLb9) {eval(\"/*@cc_on var cheburgenDJx6 = new Date() @*/\");cheburgenDJx6[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenDJx6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenQx5 = cheburgenLb9[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\"}``;``h``t``a``P``t``r``o``h``S``.``1``b``G``n``e``g``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``t" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``1``+``1``=``4``t``H``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``b``X``n``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\"/``*``@`` ``}``;``5``x``Q``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\"/``*``@`` ``}``;``9``b``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s9  = "function cheburgenZy5(cheburgenLb9) {eval(\"/*@cc_on var cheburgenDJx6 = new Date() @*/\");cheburgenDJx6[\"setUTC\"+\"Seconds\"]" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``7``f``T``n``e``g``r``u``b``e``h``c`` ``+`` ``8``b``F`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\"/``*``@`` ``}``;``)``3``c``F``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``h``P``H`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``i" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZy5(\";``1``+``1``=``4``t``H``n``e``g``r``u``b``e``h``c`` ``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}