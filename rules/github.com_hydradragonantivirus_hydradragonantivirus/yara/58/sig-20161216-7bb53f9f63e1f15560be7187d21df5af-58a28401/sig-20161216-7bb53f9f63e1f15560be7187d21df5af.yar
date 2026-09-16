rule sig_20161216_7bb53f9f63e1f15560be7187d21df5af {
  meta:
    description = "datamaliciousorder - file 20161216_7bb53f9f63e1f15560be7187d21df5af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c613dbc6ed5493576f54939e1fd05a232739d10d8914d739b322d04b7f30709"

  strings:
    $s1  = "function methZp0(methNc4) {eval(\"/*@cc_on var methKv8 = new Date() @*/\");methKv8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methZp0(methNc4) {eval(\"/*@cc_on var methKv8 = new Date() @*/\");methKv8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMd1 = methNc4[\"sp\"+\"lit\"](\"``\"); return methMd1[\"reverse\"]()[" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``k``M``L``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``z``F``h``t``e``m``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``)``\\x22``d``i``e``z``d``f``l``z``/``z``c``.``r``a``z`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\"/``*``@`` ``}``;``4``c``N``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``)``\\x22``d``i``e``z``d``f``l``z``/``z``c``.``r``a``z`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\"/``*``@`` ``}``;``1``d``M``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\"/``*``@`` ``}``;``0``n``X``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\"/``*``@`` ``}``;``)``3``m``G``h``t``e``m``(``3``u``X``h``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``)``\\x22``4``z``p``i``r``a``z``/``m``o``c``.``a``d``i`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``d``V``Q``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZp0(\"/``*``@`` ``}``;``4``c``N``h``t``e``m`` ``n``r``u``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}