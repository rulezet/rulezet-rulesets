rule sig_20161216_81144ddedcb5ed90e4eabb8391d7003d {
  meta:
    description = "datamaliciousorder - file 20161216_81144ddedcb5ed90e4eabb8391d7003d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66ab9c3042f6c60d42905b436fc5e5b9d47cc14b1f0742460267573ddd20cde1"

  strings:
    $s1  = "function methVi5(methVJp1) {eval(\"/*@cc_on var methELq9 = new Date() @*/\");methELq9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methHy3 = methVJp1[\"sp\"+\"lit\"](\"``\"); return methHy3[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\"/``*``@`` ``}``;``)``5``k``U``O``h``t``e``m``(``6``s``L``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``1``+``1``=``5``i``A``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\"/``*``@`` ``}``;``)``5``k``U``O``h``t``e``m``(``6``s``L``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s9  = "function methVi5(methVJp1) {eval(\"/*@cc_on var methELq9 = new Date() @*/\");methELq9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``0`` ``=`` ``2``f``Z``K``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\"/``*``@`` ``}``;``3``y``H``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``e``I``J``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVi5(\"}``;``h``t``a``P``t``r``o``h``S``.``1``b``F``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}