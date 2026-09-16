rule sig_20161216_1e0fdf91ee8309dcd93926cff10baaae {
  meta:
    description = "datamaliciousorder - file 20161216_1e0fdf91ee8309dcd93926cff10baaae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "916cd5715f8fefeb71cb00965ea1c701d33acbfb287ecf7e9062f13ecc6a258f"

  strings:
    $s1  = "function methDZu3(methVs9) {eval(\"/*@cc_on var methIo3 = new Date() @*/\");methIo3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``0`` ``=`` ``4``l``Z``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\"/``*``@`` ``}``;``3``y``Q``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\"/``*``@`` ``}``;``)``1``z``E``h``t``e``m``(``4``y``I``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s8  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUy0 = methVs9[\"sp\"+\"lit\"](\"``\"); return methUy0[\"reverse\"]()" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``1``+``1``=``1``f``U``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``j``Y``J``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\"/``*``@`` ``}``;``0``y``U``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDZu3(\"/``*``@`` ``}``;``9``s``V``h``t``e``m`` ``n``r``u``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}