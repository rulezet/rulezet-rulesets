rule sig_20161216_632eaec1ee43083793025f5365544e13 {
  meta:
    description = "datamaliciousorder - file 20161216_632eaec1ee43083793025f5365544e13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfa0f4e6f2958e7b7ba8023e29610669f58417eb7e25909f76a20a735275be75"

  strings:
    $s1  = "function methSPt6(methFDz1) {eval(\"/*@cc_on var methFd7 = new Date() @*/\");methFd7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``a``N``h`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``m``Z``B``h`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``1``+``1``=``8``i``X``F``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\"/``*``@`` ``}``;``)``8``p``O``E``h``t``e``m``(``2``i``M`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\"}``;``h``t``a``P``t``r``o``h``S``.``8``e``Q``h``t``e``m`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPt6(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``." ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}