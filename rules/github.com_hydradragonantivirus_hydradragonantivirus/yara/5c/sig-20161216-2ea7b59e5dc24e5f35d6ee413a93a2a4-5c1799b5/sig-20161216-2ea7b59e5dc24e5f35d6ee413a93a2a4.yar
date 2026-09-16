rule sig_20161216_2ea7b59e5dc24e5f35d6ee413a93a2a4 {
  meta:
    description = "datamaliciousorder - file 20161216_2ea7b59e5dc24e5f35d6ee413a93a2a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f55df348ba2d1dc0f16b494ba3fc2f1d0d2858e8756b045164d584173aa4a35"

  strings:
    $s1  = "function cheburgenBu9(cheburgenUWi3) {eval(\"/*@cc_on var cheburgenQEr5 = new Date() @*/\");cheburgenQEr5[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``p``C``n``e``g``r`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``1``+``1``=``4``r``R``E``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\"/``*``@`` ``}``;``7``o``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\"/``*``@`` ``}``;``3``i``W``U``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "rn cheburgenNi4[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``)``\\x22``p``a``h``5``d``d``w``b``c``5``/``m``o``c``." ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``p``C``n``e``g``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``g``F``n`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``s" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``v``P``n``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``s" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBu9(\"/``*``@`` ``}``;``4``i``N``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}