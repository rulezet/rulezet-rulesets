rule sig_20161215_651f784c751cd238789e5bfc2da4b218 {
  meta:
    description = "datamaliciousorder - file 20161215_651f784c751cd238789e5bfc2da4b218.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe19b99842776f7ae0bdc69eb38ef77b1d56b5e3765ce292ffed669c2ded2281"

  strings:
    $s1  = "20\");if (cheburgenNb3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenOs5 = cheburgenNj4[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenUNd9(cheburgenNj4) {eval(\"/*@cc_on var cheburgenNb3 = new Date() @*/\");cheburgenNb3[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\"/``*``@`` ``}``;``5``s``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``f``T``n``e" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``0`` ``=`` ``7``p``C``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\"/``*``@`` ``}``;``5``s``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``q``F``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\"/``*``@`` ``}``;``1``s``X``I``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\"/``*``@`` ``}``;``)``7``e``H``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\"/``*``@`` ``}``;``)``7``e``H``n``e``g``r``u``b``e``h``c" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``f``T``n``e" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``)``\\x22``\\x22`` ``+`` ``9``r``P``n``e``g``r``u``b`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUNd9(\";``7``z``N``Y``n``e``g``r``u``b``e``h``c`` ``+`` ``6``h" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}