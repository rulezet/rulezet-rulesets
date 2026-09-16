rule sig_20161216_af0939cc758f4a330ffa9b5056711e3f {
  meta:
    description = "datamaliciousorder - file 20161216_af0939cc758f4a330ffa9b5056711e3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b825081fca54625b8470f588baffd36e56772e532ff1a274c8a2915142ccb838"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUFk9 = methDf1[\"sp\"+\"lit\"](\"``\"); return methUFk9[\"reverse" ascii
    $s2  = "function methRk9(methDf1) {eval(\"/*@cc_on var methZTy7 = new Date() @*/\");methZTy7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``1``+``1``=``6``n``J``Y``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``4``t``U``U``h``t``e``m`` ``+`` ``4``t``B``h``t``e``m``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\"/``*``@`` ``}``;``9``k``F``U``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``0`` ``=`` ``8``e``L``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\"/``*``@`` ``}``;``7``y``P``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\"/``*``@`` ``}``;``1``f``D``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\"}``;``h``t``a``P``t``r``o``h``S``.``4``v``K``h``t``e``m``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\"/``*``@`` ``}``;``9``k``F``U``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n`" ascii
    $s19 = "function methRk9(methDf1) {eval(\"/*@cc_on var methZTy7 = new Date() @*/\");methZTy7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRk9(\";``1``+``1``=``6``n``J``Y``h``t``e``m`` ``r``a``v``;``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}