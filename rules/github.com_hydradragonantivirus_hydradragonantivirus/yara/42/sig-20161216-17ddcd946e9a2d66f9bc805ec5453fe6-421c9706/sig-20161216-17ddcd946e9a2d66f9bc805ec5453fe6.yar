rule sig_20161216_17ddcd946e9a2d66f9bc805ec5453fe6 {
  meta:
    description = "datamaliciousorder - file 20161216_17ddcd946e9a2d66f9bc805ec5453fe6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3d6f40658922d812272691a9d40343a1dc6911c7a02a356b12c0da261d9740a"

  strings:
    $s1  = "0\");if (cheburgenGc9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenIx4 = cheburgenVw5[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenNe0(cheburgenVw5) {eval(\"/*@cc_on var cheburgenGc9 = new Date() @*/\");cheburgenGc9[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\"\")), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\"/``*``@`` ``}``;``4``x``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\"/``*``@`` ``}``;``)``0``y``O``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``." ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\"}``;``h``t``a``P``t``r``o``h``S``.``9``u``L``n``e``g``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``1``+``1``=``1``r``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\"/``*``@`` ``}``;``)``0``y``O``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``1``+``1``=``1``r``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\"/``*``@`` ``}``;``4``x``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``0`` ``=`` ``2``l``F``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``0`` ``=`` ``2``l``F``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``)``\\x22``\\x22`` ``+`` ``1``c``E``n``e``g``r``u``b``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``b``S``n``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNe0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}