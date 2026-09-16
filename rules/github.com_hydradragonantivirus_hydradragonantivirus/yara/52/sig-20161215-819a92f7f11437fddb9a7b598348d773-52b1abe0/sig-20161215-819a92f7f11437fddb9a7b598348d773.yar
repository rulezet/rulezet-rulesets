rule sig_20161215_819a92f7f11437fddb9a7b598348d773 {
  meta:
    description = "datamaliciousorder - file 20161215_819a92f7f11437fddb9a7b598348d773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2858f5afc07b6ac2a2de5d95c4a9bd432ce1f2b6e6a71beef2c7362a32b2ba5"

  strings:
    $s1  = "0\");if (cheburgenTi0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenVFc7 = cheburgenQb3[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenGj7(cheburgenQb3) {eval(\"/*@cc_on var cheburgenTi0 = new Date() @*/\");cheburgenTi0[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``)``\\x22``b``l``m``6``d``b``u``y``z``/``u``r``.``a``r" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``1``+``1``=``6``m``V``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``t``B``n`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\"/``*``@`` ``}``;``2``r``T``T``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``)``\\x22``b``l``m``6``d``b``u``y``z``/``u``r``.``a``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\"}``;``h``t``a``P``t``r``o``h``S``.``6``a``E``C``n``e``g`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\"/``*``@`` ``}``;``3``b``Q``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``y``G``W``n`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\"/``*``@`` ``}``;``3``b``Q``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``8``a``R``R``n``e``g``r``u``b``e``h``c`` ``+`` ``2``s`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGj7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}