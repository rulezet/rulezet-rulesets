rule sig_20161216_bcf3cc30512ee8c2a6f42bf812f6512f {
  meta:
    description = "datamaliciousorder - file 20161216_bcf3cc30512ee8c2a6f42bf812f6512f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d5acd8501b819acbdd49e96b663859c9e14989536d2197fce6b302099e17225"

  strings:
    $s1  = "function methTTi7(methVIh5) {eval(\"/*@cc_on var methEi0 = new Date() @*/\");methEi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``0`` ``=`` ``2``f``J``I``h``t``e``m`` ``r``a``v\"))), " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\"/``*``@`` ``}``;``0``r``H``Y``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\"/``*``@`` ``}``;``0``r``H``Y``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``8``e``M``h``t``e``m`` ``+`` ``1``g``O``D``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``1``+``1``=``6``d``S``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\"/``*``@`` ``}``;``4``e``E``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "function methTTi7(methVIh5) {eval(\"/*@cc_on var methEi0 = new Date() @*/\");methEi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``d``K``E``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\"/``*``@`` ``}``;``4``e``E``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``0`` ``=`` ``2``f``J``I``h``t``e``m`` ``r``a``v\"))), " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``x``G``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\"/``*``@`` ``}``;``)``4``f``F``h``t``e``m``(``0``m``J``P`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\"}``;``h``t``a``P``t``r``o``h``S``.``0``b``Y``R``h``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTTi7(\"\"))), 1);//////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}