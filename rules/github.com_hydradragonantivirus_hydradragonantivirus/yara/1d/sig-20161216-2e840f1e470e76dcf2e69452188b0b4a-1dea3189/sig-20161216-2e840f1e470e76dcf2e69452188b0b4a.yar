rule sig_20161216_2e840f1e470e76dcf2e69452188b0b4a {
  meta:
    description = "datamaliciousorder - file 20161216_2e840f1e470e76dcf2e69452188b0b4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83901f92dbdee18d4af950310e520d61a367976d3062c4aab8f26b44c00a0c5b"

  strings:
    $s1  = "function methUGf6(methGq3) {eval(\"/*@cc_on var methVGt1 = new Date() @*/\");methVGt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methJLw0 = methGq3[\"sp\"+\"lit\"](\"``\"); return methJLw0[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\"/``*``@`` ``}``;``3``q``G``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``6``k``N``h``t``e``m`` ``+`` ``6``h``B``h``t``e``m``=`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\"/``*``@`` ``}``;``5``p``Z``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\"/``*``@`` ``}``;``)``4``o``N``T``h``t``e``m``(``6``g``K`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\"}``;``h``t``a``P``t``r``o``h``S``.``0``c``N``h``t``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``j``M``E`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``1``+``1``=``3``m``O``Y``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``h``J``N``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUGf6(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}