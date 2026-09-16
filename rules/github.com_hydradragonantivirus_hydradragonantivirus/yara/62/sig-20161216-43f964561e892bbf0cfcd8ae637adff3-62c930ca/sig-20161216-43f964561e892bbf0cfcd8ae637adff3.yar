rule sig_20161216_43f964561e892bbf0cfcd8ae637adff3 {
  meta:
    description = "datamaliciousorder - file 20161216_43f964561e892bbf0cfcd8ae637adff3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf7d36e74f81163963303c9a1cb1bdedda80750f17d3478300dc8041108ef85b"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZv1 = methNl3[\"sp\"+\"lit\"](\"``\"); return methZv1[\"reverse" ascii
    $s2  = "function methIOh8(methNl3) {eval(\"/*@cc_on var methVKp7 = new Date() @*/\");methVKp7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\"/``*``@`` ``}``;``1``v``Z``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\"}``;``h``t``a``P``t``r``o``h``S``.``2``z``J``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``0`` ``=`` ``7``v``U``Q``h``t``e``m`` ``r``a``v\"))), " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\"/``*``@`` ``}``;``3``l``N``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``r``R``E`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``r``R``E`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\"/``*``@`` ``}``;``)``3``j``Z``I``h``t``e``m``(``2``k``V`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\"}``;``h``t``a``P``t``r``o``h``S``.``2``z``J``h``t``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``1``+``1``=``4``y``E``W``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``l``K``h``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\";``8``i``E``H``h``t``e``m`` ``+`` ``8``i``R``J``h``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOh8(\"/``*``@`` ``}``;``7``f``A``h``t``e``m`` ``n``r``u``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}