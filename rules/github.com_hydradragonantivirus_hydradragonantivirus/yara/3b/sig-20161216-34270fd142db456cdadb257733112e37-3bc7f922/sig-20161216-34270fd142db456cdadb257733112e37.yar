rule sig_20161216_34270fd142db456cdadb257733112e37 {
  meta:
    description = "datamaliciousorder - file 20161216_34270fd142db456cdadb257733112e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adad7a163cbaa26134a42aea06d0efa2dc1ac4e5ffabe9cfffb3fac37bf27601"

  strings:
    $s1  = "function cheburgenUBb7(cheburgenGSm1) {eval(\"/*@cc_on var cheburgenMg0 = new Date() @*/\");cheburgenMg0[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``b``C``n``e" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\"/``*``@`` ``}``;``1``m``S``G``n``e``g``r``u``b``e``h``c" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``z``T``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``1``+``1``=``3``r``G``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``\\x22``\\x22`` ``+`` ``8``a``N``A``n``e``g``r``u`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``1``+``1``=``3``r``G``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``\\x22``\\x22`` ``+`` ``8``a``N``A``n``e``g``r``u`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``5``z``S``M``n``e``g``r``u``b``e``h``c`` ``+`` ``7``l" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``0`` ``=`` ``4``q``K``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\"}``;``h``t``a``P``t``r``o``h``S``.``1``l``V``n``e``g``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\"/``*``@`` ``}``;``8``y``J``H``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUBb7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}