rule sig_20161216_a937f704e59d542848eb685b78d2150c {
  meta:
    description = "datamaliciousorder - file 20161216_a937f704e59d542848eb685b78d2150c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8856bba98cb44d1f75b573f983aa05031fa1d1f83678e857d3312bdbc3cff92"

  strings:
    $s1  = "function methSm4(methRp1) {eval(\"/*@cc_on var methQt3 = new Date() @*/\");methQt3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methSm4(methRp1) {eval(\"/*@cc_on var methQt3 = new Date() @*/\");methQt3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``e``Y``K``h``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``1``+``1``=``1``i``J``L``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\"/``*``@`` ``}``;``1``p``R``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``1``+``1``=``1``i``J``L``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\"/``*``@`` ``}``;``8``h``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``p``I``h``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\"}``;``h``t``a``P``t``r``o``h``S``.``9``t``R``C``h``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\"}``;``h``t``a``P``t``r``o``h``S``.``9``t``R``C``h``t``e``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSm4(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}