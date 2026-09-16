rule sig_20161216_3ec4af26a18d573ad0751e84f6df0abb {
  meta:
    description = "datamaliciousorder - file 20161216_3ec4af26a18d573ad0751e84f6df0abb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7c97e195afec7d040f8ea8d82cb833a9b7eb044b82aa904ce3d101477ec566b"

  strings:
    $s1  = "\"20\");if (cheburgenRRe9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenXn2 = cheburgenUh7[\"split\"](\"`" ascii
    $s2  = "function cheburgenQi0(cheburgenUh7) {eval(\"/*@cc_on var cheburgenRRe9 = new Date() @*/\");cheburgenRRe9[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``0`` ``=`` ``5``y``Z``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``n``E``L``n`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``6``a``E``n``e``g``r``u``b``e``h``c`` ``+`` ``0``o``Q`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``d" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\"\")), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``0`` ``=`` ``5``y``Z``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``k" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\"/``*``@`` ``}``;``)``9``m``Y``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\"/``*``@`` ``}``;``7``h``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\"/``*``@`` ``}``;``7``h``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``)``\\x22``\\x22`` ``+`` ``4``u``C``I``n``e``g``r``u``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``q``D``R`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQi0(\"/``*``@`` ``}``;``)``9``m``Y``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}