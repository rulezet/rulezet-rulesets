rule sig_20161216_a023f8b1795d5beae56aee55bf0dc89a {
  meta:
    description = "datamaliciousorder - file 20161216_a023f8b1795d5beae56aee55bf0dc89a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a7e4f42e5f8fd17fd956edf09d3c5d7f7f5327baaf8e366aff173508338a0c"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methIo2 = methWEi4[\"sp\"+\"lit\"](\"``\"); return methIo2[\"reverse" ascii
    $s2  = "function methRf6(methWEi4) {eval(\"/*@cc_on var methNCp9 = new Date() @*/\");methNCp9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\"}``;``h``t``a``P``t``r``o``h``S``.``0``s``H``E``h``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``7``g``A``h``t``e``m`` ``+`` ``7``q``G``B``h``t``e``m``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\"/``*``@`` ``}``;``)``7``g``C``N``h``t``e``m``(``5``g``J``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``7``g``A``h``t``e``m`` ``+`` ``7``q``G``B``h``t``e``m``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\"/``*``@`` ``}``;``4``i``E``W``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``y``H``h``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRf6(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}