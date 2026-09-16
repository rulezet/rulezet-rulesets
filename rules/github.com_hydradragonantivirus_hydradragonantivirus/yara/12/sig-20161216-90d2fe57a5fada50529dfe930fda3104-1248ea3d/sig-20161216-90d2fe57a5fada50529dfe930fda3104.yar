rule sig_20161216_90d2fe57a5fada50529dfe930fda3104 {
  meta:
    description = "datamaliciousorder - file 20161216_90d2fe57a5fada50529dfe930fda3104.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f89da5ba2bff9edafd681020e49cea1bc1327f991b631f4a70d7a4eb15b7478f"

  strings:
    $s1  = "function methQWt6(methORf5) {eval(\"/*@cc_on var methKp3 = new Date() @*/\");methKp3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "function methQWt6(methORf5) {eval(\"/*@cc_on var methKp3 = new Date() @*/\");methKp3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"/``*``@`` ``}``;``5``f``R``O``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"/``*``@`` ``}``;``1``r``I``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"}``;``h``t``a``P``t``r``o``h``S``.``1``k``H``O``h``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"}``;``h``t``a``P``t``r``o``h``S``.``1``k``H``O``h``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"/``*``@`` ``}``;``1``r``I``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"/``*``@`` ``}``;``7``n``L``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``g``K``I``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``t``T``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``1``+``1``=``3``y``D``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"/``*``@`` ``}``;``)``4``o``X``S``h``t``e``m``(``1``l``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQWt6(\"\"))), 1);//////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}