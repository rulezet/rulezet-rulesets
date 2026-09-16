rule sig_20161216_4db1e3184119b123dfb3ee349a762c2e {
  meta:
    description = "datamaliciousorder - file 20161216_4db1e3184119b123dfb3ee349a762c2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af2bb5d4196518a2d5f56457ca14b4faf816c15f9b0b129c64d42416b282dd14"

  strings:
    $s1  = "20\");if (cheburgenKf2[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenFq5 = cheburgenNo6[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenROr3(cheburgenNo6) {eval(\"/*@cc_on var cheburgenKf2 = new Date() @*/\");cheburgenKf2[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\"/``*``@`` ``}``;``)``7``u``S``Z``n``e``g``r``u``b``e``h" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``8``e``M``Q``n``e``g``r``u``b``e``h``c`` ``+`` ``8``n" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``z``H``n``e" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\"/``*``@`` ``}``;``6``o``N``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\"}``;``h``t``a``P``t``r``o``h``S``.``4``r``O``n``e``g``r" ascii
    $s13 = "function cheburgenROr3(cheburgenNo6) {eval(\"/*@cc_on var cheburgenKf2 = new Date() @*/\");cheburgenKf2[\"setUTC\"+\"Seconds\"](" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``1``+``1``=``1``o``I``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``1``+``1``=``1``o``I``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``0`` ``=`` ``2``c``M``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenROr3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}