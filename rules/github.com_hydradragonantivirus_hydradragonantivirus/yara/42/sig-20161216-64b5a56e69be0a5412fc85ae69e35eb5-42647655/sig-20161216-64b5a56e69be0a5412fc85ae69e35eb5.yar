rule sig_20161216_64b5a56e69be0a5412fc85ae69e35eb5 {
  meta:
    description = "datamaliciousorder - file 20161216_64b5a56e69be0a5412fc85ae69e35eb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c22e2e850ca0c38a67a76a71f74975841482554e7a904ced4c85339ae5131a93"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methIWn2 = methVr5[\"sp\"+\"lit\"](\"``\"); return methIWn2[\"reverse" ascii
    $s2  = "function methNd7(methVr5) {eval(\"/*@cc_on var methBZn2 = new Date() @*/\");methBZn2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\"/``*``@`` ``}``;``6``j``U``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``.`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``1``+``1``=``0``d``E``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\"/``*``@`` ``}``;``5``r``V``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\"/``*``@`` ``}``;``)``1``r``I``N``h``t``e``m``(``2``u``L``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``6``s``G``h``t``e``m`` ``+`` ``4``x``N``X``h``t``e``m``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``q``P``h``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\"/``*``@`` ``}``;``2``n``W``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``.`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\";``0`` ``=`` ``8``m``T``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNd7(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}