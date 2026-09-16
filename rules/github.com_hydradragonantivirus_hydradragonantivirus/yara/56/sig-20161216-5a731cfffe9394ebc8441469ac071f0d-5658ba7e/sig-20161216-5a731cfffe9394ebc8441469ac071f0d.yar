rule sig_20161216_5a731cfffe9394ebc8441469ac071f0d {
  meta:
    description = "datamaliciousorder - file 20161216_5a731cfffe9394ebc8441469ac071f0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c597bb7fcd3099d4cb2102a2ff2a712218eed6a482aa5fc3dd613877bbb1140"

  strings:
    $s1  = "function methNr9(methTb7) {eval(\"/*@cc_on var methDy1 = new Date() @*/\");methDy1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methNr9(methTb7) {eval(\"/*@cc_on var methDy1 = new Date() @*/\");methDy1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\"/``*``@`` ``}``;``7``b``T``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\"/``*``@`` ``}``;``)``4``b``L``h``t``e``m``(``5``q``S``h``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``z``V``K``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\"/``*``@`` ``}``;``1``h``S``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\"/``*``@`` ``}``;``1``h``S``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``0`` ``=`` ``5``p``M``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNr9(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}