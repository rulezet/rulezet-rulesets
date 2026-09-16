rule sig_20161216_932a3f234fd09fd598da5e6f0641ff51 {
  meta:
    description = "datamaliciousorder - file 20161216_932a3f234fd09fd598da5e6f0641ff51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80f5b10bf1e16bf85c6e8ccf037477ddc8fb794a11c442e507af1f5226f420f3"

  strings:
    $s1  = "function methIHy8(methVn3) {eval(\"/*@cc_on var methIPx0 = new Date() @*/\");methIPx0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methPv1 = methVn3[\"sp\"+\"lit\"](\"``\"); return methPv1[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``." ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``1``+``1``=``0``y``W``X``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\"/``*``@`` ``}``;``6``f``Q``V``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``0``2``y``V``T``h``t``e``m`` ``+`` ``0``d``B``h``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\"/``*``@`` ``}``;``3``n``V``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\"/``*``@`` ``}``;``6``f``Q``V``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\"}``;``h``t``a``P``t``r``o``h``S``.``1``a``D``h``t``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\"/``*``@`` ``}``;``1``v``P``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``." ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``v``I``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``0`` ``=`` ``9``r``F``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIHy8(\"\"))), 1);//////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}