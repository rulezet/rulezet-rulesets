rule sig_20161216_76944f7163e2dbc1405a1473a0679cd7 {
  meta:
    description = "datamaliciousorder - file 20161216_76944f7163e2dbc1405a1473a0679cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d36107e709dfa274802543830fe60692bd29477d9c4244f399c596a5a86e5cd"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUv3 = methZUy3[\"sp\"+\"lit\"](\"``\"); return methUv3[\"revers" ascii
    $s2  = "function methIOg2(methZUy3) {eval(\"/*@cc_on var methALr3 = new Date() @*/\");methALr3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``0`` ``=`` ``1``a``E``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``o``Y``F`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\"/``*``@`` ``}``;``4``g``O``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\"/``*``@`` ``}``;``3``y``U``Z``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\"/``*``@`` ``}``;``3``v``U``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``0`` ``=`` ``1``a``E``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``4``p``A``h``t``e``m`` ``+`` ``1``y``O``Y``h``t``e``m`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOg2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}