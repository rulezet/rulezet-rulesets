rule sig_20161216_e5da705bb5dae05e91addfb64c3badb5 {
  meta:
    description = "datamaliciousorder - file 20161216_e5da705bb5dae05e91addfb64c3badb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25046bb5c4030649d44dedec04286c0d234dbad1886792380872e86f4cc6d03e"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZDj8 = methLy9[\"sp\"+\"lit\"](\"``\"); return methZDj8[\"reverse" ascii
    $s2  = "function methJp2(methLy9) {eval(\"/*@cc_on var methIAv3 = new Date() @*/\");methIAv3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\"/``*``@`` ``}``;``0``v``L``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``3``z``O``U``h``t``e``m`` ``+`` ``0``i``M``K``h``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``3``z``O``U``h``t``e``m`` ``+`` ``0``i``M``K``h``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``h``C``h``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``o``C``N``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\"/``*``@`` ``}``;``9``y``L``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\"/``*``@`` ``}``;``0``v``L``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``o``C``N``h``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``.`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``0`` ``=`` ``5``k``D``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJp2(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}