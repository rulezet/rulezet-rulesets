rule sig_20161216_bdf8aa73166143cb43c6bdf0d54ae847 {
  meta:
    description = "datamaliciousorder - file 20161216_bdf8aa73166143cb43c6bdf0d54ae847.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4be1c9b0c18809b39555375d3812b626dfe8deca7f30448666eda086eba4c14"

  strings:
    $s1  = "function methRXd8(methSFw5) {eval(\"/*@cc_on var methYz2 = new Date() @*/\");methYz2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\"/``*``@`` ``}``;``5``w``F``S``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``8``z``C``T``h``t``e``m`` ``+`` ``8``v``L``M``h``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``m``D``X`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``1``+``1``=``1``l``Z``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``0`` ``=`` ``0``y``H``Z``h``t``e``m`` ``r``a``v\"))), " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\"/``*``@`` ``}``;``5``w``F``S``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``8``z``C``T``h``t``e``m`` ``+`` ``8``v``L``M``h``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``p``R``Q``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\"}``;``h``t``a``P``t``r``o``h``S``.``0``s``P``W``h``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRXd8(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}