rule sig_20161216_3bd1d6de297a0281205f48eb3861dc68 {
  meta:
    description = "datamaliciousorder - file 20161216_3bd1d6de297a0281205f48eb3861dc68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad68807abd5c52141dab4036cad8f5ff50d79e20c95c78dab1fca6a5ff3697c"

  strings:
    $s1  = "function cheburgenWd4(cheburgenCBy4) {eval(\"/*@cc_on var cheburgenHy6 = new Date() @*/\");cheburgenHy6[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenHy6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenUo5 = cheburgenCBy4[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``v``E``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\"/``*``@`` ``}``;``5``o``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\"/``*``@`` ``}``;``4``y``B``C``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\"}``;``h``t``a``P``t``r``o``h``S``.``1``h``N``n``e``g``r`" ascii
    $s9  = "function cheburgenWd4(cheburgenCBy4) {eval(\"/*@cc_on var cheburgenHy6 = new Date() @*/\");cheburgenHy6[\"setUTC\"+\"Seconds\"](" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``8``y``S``J``n``e``g``r``u``b``e``h``c`` ``+`` ``3``w`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``8``y``S``J``n``e``g``r``u``b``e``h``c`` ``+`` ``3``w`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\"/``*``@`` ``}``;``)``8``w``Y``M``n``e``g``r``u``b``e``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``v``E``n`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\"/``*``@`` ``}``;``4``h``X``D``n``e``g``r``u``b``e``h``c`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``g" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWd4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``w``E``F``n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}