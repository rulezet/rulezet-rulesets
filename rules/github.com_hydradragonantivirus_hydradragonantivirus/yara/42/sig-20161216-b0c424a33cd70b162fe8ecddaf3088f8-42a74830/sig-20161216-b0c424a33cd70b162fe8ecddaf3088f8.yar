rule sig_20161216_b0c424a33cd70b162fe8ecddaf3088f8 {
  meta:
    description = "datamaliciousorder - file 20161216_b0c424a33cd70b162fe8ecddaf3088f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06f9ac2f97f95a40b3a09e2167413a63f567d3bb2f053b7efffaadce1ac8559d"

  strings:
    $s1  = "function methVCw3(methLNi1) {eval(\"/*@cc_on var methWw7 = new Date() @*/\");methWw7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``0`` ``=`` ``9``g``U``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``8``u``E``K``h``t``e``m`` ``+`` ``8``i``L``T``h``t``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\"/``*``@`` ``}``;``1``i``N``L``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\"/``*``@`` ``}``;``)``3``x``I``h``t``e``m``(``6``t``P``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``t``N``V``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\"}``;``h``t``a``P``t``r``o``h``S``.``0``w``Y``Y``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\"/``*``@`` ``}``;``)``3``x``I``h``t``e``m``(``6``t``P``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVCw3(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}