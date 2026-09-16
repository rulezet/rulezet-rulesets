rule sig_20161216_5d1a89096bff90ba1934bd3ee1bc9d97 {
  meta:
    description = "datamaliciousorder - file 20161216_5d1a89096bff90ba1934bd3ee1bc9d97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae833e6819d72720bed6a1e80f5d6c853f3e180ba08a6a5473ec60ac0925f7f4"

  strings:
    $s1  = "function cheburgenXp0(cheburgenNu0) {eval(\"/*@cc_on var cheburgenCi4 = new Date() @*/\");cheburgenCi4[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenCi4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenCv7 = cheburgenNu0[\"split\"](\"``\")" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``5``a``X``n``e``g``r``u``b``e``h``c`` ``+`` ``7``a``M`" ascii
    $s4  = "eburgenCv7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``k" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\"/``*``@`` ``}``;``0``u``N``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``0`` ``=`` ``3``o``O``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\"/``*``@`` ``}``;``)``1``i``B``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``d" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``1``+``1``=``9``o``R``R``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``5``a``X``n``e``g``r``u``b``e``h``c`` ``+`` ``7``a``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\"/``*``@`` ``}``;``7``v``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\"}``;``h``t``a``P``t``r``o``h``S``.``4``z``L``n``e``g``r`" ascii
    $s18 = "function cheburgenXp0(cheburgenNu0) {eval(\"/*@cc_on var cheburgenCi4 = new Date() @*/\");cheburgenCi4[\"setUTC\"+\"Seconds\"](" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXp0(\"/``*``@`` ``}``;``4``d``F``G``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}