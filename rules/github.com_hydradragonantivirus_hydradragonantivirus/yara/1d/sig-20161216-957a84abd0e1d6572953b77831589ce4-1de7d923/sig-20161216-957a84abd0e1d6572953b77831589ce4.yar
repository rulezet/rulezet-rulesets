rule sig_20161216_957a84abd0e1d6572953b77831589ce4 {
  meta:
    description = "datamaliciousorder - file 20161216_957a84abd0e1d6572953b77831589ce4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c5dc3c912ac11146ef2b898842123e972915a4418c08312168e8d05189c966f"

  strings:
    $s1  = "function methZZh7(methINo1) {eval(\"/*@cc_on var methLFr1 = new Date() @*/\");methLFr1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUYs5 = methINo1[\"sp\"+\"lit\"](\"``\"); return methUYs5[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``." ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``t``P``h``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\"/``*``@`` ``}``;``1``o``N``I``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\"/``*``@`` ``}``;``5``s``Y``U``h``t``e``m`` ``n``r``u``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "function methZZh7(methINo1) {eval(\"/*@cc_on var methLFr1 = new Date() @*/\");methLFr1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``t``P``h``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``0`` ``=`` ``3``w``W``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``." ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZZh7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}