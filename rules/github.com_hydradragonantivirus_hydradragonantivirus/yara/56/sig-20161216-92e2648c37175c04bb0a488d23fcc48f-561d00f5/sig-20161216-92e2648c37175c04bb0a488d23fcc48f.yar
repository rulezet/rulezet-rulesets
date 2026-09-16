rule sig_20161216_92e2648c37175c04bb0a488d23fcc48f {
  meta:
    description = "datamaliciousorder - file 20161216_92e2648c37175c04bb0a488d23fcc48f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3016d4f9889758103627926056332cce1b675f97b8dfa62556c7142d88d703c2"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methXLf1 = methFKo6[\"sp\"+\"lit\"](\"``\"); return methXLf1[\"rever" ascii
    $s2  = "function methYf7(methFKo6) {eval(\"/*@cc_on var methJXr0 = new Date() @*/\");methJXr0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``1``+``1``=``4``d``U``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\"}``;``h``t``a``P``t``r``o``h``S``.``3``k``B``h``t``e``m``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\"/``*``@`` ``}``;``6``b``V``E``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\"}``;``h``t``a``P``t``r``o``h``S``.``3``k``B``h``t``e``m``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\"/``*``@`` ``}``;``)``9``q``N``O``h``t``e``m``(``6``o``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\"/``*``@`` ``}``;``6``b``V``E``h``t``e``m`` ``n``r``u``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``8``y``K``N``h``t``e``m`` ``+`` ``7``h``H``H``h``t``e``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``0`` ``=`` ``9``u``D``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``0`` ``=`` ``9``u``D``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``a``Z``h``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYf7(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}