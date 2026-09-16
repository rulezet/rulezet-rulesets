rule sig_20161215_18d57e86f4e69148d6cedbc0eefd10f5 {
  meta:
    description = "datamaliciousorder - file 20161215_18d57e86f4e69148d6cedbc0eefd10f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a169e25d786cd759bc507fb1da5eac3b10b5e12f463b3881175cb34e78c3a0"

  strings:
    $s1  = "function cheburgenLu7(cheburgenEKy0) {eval(\"/*@cc_on var cheburgenBp9 = new Date() @*/\");cheburgenBp9[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenBp9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenUTa6 = cheburgenEKy0[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"/``*``@`` ``}``;``0``y``K``E``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"/``*``@`` ``}``;``6``a``T``U``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"}``;``h``t``a``P``t``r``o``h``S``.``8``b``R``D``n``e``g`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``y``B``n``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"}``;``h``t``a``P``t``r``o``h``S``.``8``b``R``D``n``e``g`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"/``*``@`` ``}``;``2``b``E``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``l" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``l" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``t``T``n`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``w" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\"/``*``@`` ``}``;``2``b``E``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLu7(\";``1``+``1``=``3``e``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}