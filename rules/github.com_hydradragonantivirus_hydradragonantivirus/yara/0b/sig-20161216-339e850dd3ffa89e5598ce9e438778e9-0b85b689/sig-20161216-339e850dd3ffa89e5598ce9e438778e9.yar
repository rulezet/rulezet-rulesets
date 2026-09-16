rule sig_20161216_339e850dd3ffa89e5598ce9e438778e9 {
  meta:
    description = "datamaliciousorder - file 20161216_339e850dd3ffa89e5598ce9e438778e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "573a89a5d59a9e95fee827f0a0873c4624d021b10a533ef0cd4fff8e42976b46"

  strings:
    $s1  = "function cheburgenEMa0(cheburgenOj5) {eval(\"/*@cc_on var cheburgenJa3 = new Date() @*/\");cheburgenJa3[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenJa3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenBg5 = cheburgenOj5[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``0``r``U``O``n``e``g``r``u``b``e``h``c`` ``+`` ``9``g" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``1``+``1``=``2``j``Z``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``0`` ``=`` ``1``x``O``G``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``)``\\x22``\\x22`` ``+`` ``1``q``F``M``n``e``g``r``u`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\"/``*``@`` ``}``;``5``g``B``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``v``A``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``0``r``U``O``n``e``g``r``u``b``e``h``c`` ``+`` ``9``g" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s19 = "function cheburgenEMa0(cheburgenOj5) {eval(\"/*@cc_on var cheburgenJa3 = new Date() @*/\");cheburgenJa3[\"setUTC\"+\"Seconds\"](" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEMa0(\";``1``+``1``=``2``j``Z``n``e``g``r``u``b``e``h``c`` ``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}