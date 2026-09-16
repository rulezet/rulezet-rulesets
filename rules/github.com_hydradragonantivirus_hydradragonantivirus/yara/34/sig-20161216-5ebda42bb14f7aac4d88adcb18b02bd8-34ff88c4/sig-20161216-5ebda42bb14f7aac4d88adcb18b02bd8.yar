rule sig_20161216_5ebda42bb14f7aac4d88adcb18b02bd8 {
  meta:
    description = "datamaliciousorder - file 20161216_5ebda42bb14f7aac4d88adcb18b02bd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f909245230eeb286b8fd46eacd33472c7806846be576aa05155a257aa5eee085"

  strings:
    $s1  = "function methQUe6(methQDt8) {eval(\"/*@cc_on var methIu5 = new Date() @*/\");methIu5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "function methQUe6(methQDt8) {eval(\"/*@cc_on var methIu5 = new Date() @*/\");methIu5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\"/``*``@`` ``}``;``8``t``D``Q``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\"/``*``@`` ``}``;``7``f``M``M``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``a``E``h``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``a``E``h``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``0`` ``=`` ``9``q``J``V``h``t``e``m`` ``r``a``v\"))), " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``)``\\x22``4``m``e``j``f``/``a``b``.``m``o``c``.``n``o" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``0``p``M``h``t``e``m`` ``+`` ``0``z``K``Z``h``t``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``)``\\x22``g``j``g``i``0``/``m``o``c``.``g``n``o``s``n" ascii
    $s17 = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMMf7 = methQDt8[\"sp\"+\"lit\"](\"``\"); return methMMf7[\"reverse" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\"}``;``h``t``a``P``t``r``o``h``S``.``0``g``X``M``h``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQUe6(\"/``*``@`` ``}``;``8``t``D``Q``h``t``e``m`` ``n``r``u``t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}