rule sig_20161216_cddb6f52c8f6496f4ce0886498732f58 {
  meta:
    description = "datamaliciousorder - file 20161216_cddb6f52c8f6496f4ce0886498732f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faa159cbce89bac88b96aafbaa75c0996045b1011a704a458abfa786d2c6a62c"

  strings:
    $s1  = "function methQa9(methYs3) {eval(\"/*@cc_on var methHd9 = new Date() @*/\");methHd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methQa9(methYs3) {eval(\"/*@cc_on var methHd9 = new Date() @*/\");methHd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\"}``;``h``t``a``P``t``r``o``h``S``.``3``o``Q``h``t``e``m``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\"/``*``@`` ``}``;``3``s``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``a``J``K``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\"/``*``@`` ``}``;``)``2``l``W``C``h``t``e``m``(``6``d``O``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``3``g``Q``h``t``e``m`` ``+`` ``7``a``L``h``t``e``m``=``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``1``+``1``=``9``c``I``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``a``J``K``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\";``0`` ``=`` ``7``s``S``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa9(\"/``*``@`` ``}``;``6``g``E``h``t``e``m`` ``n``r``u``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}