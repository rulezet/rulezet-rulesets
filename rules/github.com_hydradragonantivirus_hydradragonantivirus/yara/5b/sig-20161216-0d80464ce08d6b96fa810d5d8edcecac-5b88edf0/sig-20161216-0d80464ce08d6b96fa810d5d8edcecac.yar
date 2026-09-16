rule sig_20161216_0d80464ce08d6b96fa810d5d8edcecac {
  meta:
    description = "datamaliciousorder - file 20161216_0d80464ce08d6b96fa810d5d8edcecac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9dd324b46434b9a0da3ddb479b5996493bb2f1a81aa44e5c1e9f2d3591d5f45"

  strings:
    $s1  = "function methJQv9(methCa6) {eval(\"/*@cc_on var methAn7 = new Date() @*/\");methAn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\"/``*``@`` ``}``;``)``7``d``A``R``h``t``e``m``(``4``g``S`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``z``R``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``u``J``h``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``1``+``1``=``0``m``A``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``6``h``R``h``t``e``m`` ``+`` ``6``b``E``C``h``t``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``1``+``1``=``0``m``A``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\"/``*``@`` ``}``;``)``7``d``A``R``h``t``e``m``(``4``g``S`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJQv9(\"}``;``h``t``a``P``t``r``o``h``S``.``2``f``Z``h``t``e``m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}