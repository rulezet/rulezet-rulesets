rule sig_20161216_4e5a0ef69d0f1a29cef4ac2468357e3d {
  meta:
    description = "datamaliciousorder - file 20161216_4e5a0ef69d0f1a29cef4ac2468357e3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d59a730b49025dd282d10ea5446d2456708c84a5a2c96d9353ec60d460bca56e"

  strings:
    $s1  = "function methNDu3(methASi6) {eval(\"/*@cc_on var methGCj3 = new Date() @*/\");methGCj3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methWHj2 = methASi6[\"sp\"+\"lit\"](\"``\"); return methWHj2[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\"/``*``@`` ``}``;``6``n``Q``Y``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``1``+``1``=``5``t``Z``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\"}``;``h``t``a``P``t``r``o``h``S``.``8``p``N``h``t``e``m`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``5``x``P``E``h``t``e``m`` ``+`` ``9``f``V``h``t``e``m`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\"/``*``@`` ``}``;``6``i``S``A``h``t``e``m`` ``n``r``u``t`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``0`` ``=`` ``2``x``O``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\"/``*``@`` ``}``;``)``5``m``Q``h``t``e``m``(``0``l``O``X`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``t``C``F`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\"/``*``@`` ``}``;``)``5``m``Q``h``t``e``m``(``0``l``O``X`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNDu3(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}