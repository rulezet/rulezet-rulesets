rule sig_20161216_5cab295ed844e17f0827ef93ef6b9802 {
  meta:
    description = "datamaliciousorder - file 20161216_5cab295ed844e17f0827ef93ef6b9802.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "825a937252dfebd8c645398345c50c2321179b378fefb7a168705590192e674b"

  strings:
    $s1  = "function methIw2(methUz9) {eval(\"/*@cc_on var methJb2 = new Date() @*/\");methJb2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methIw2(methUz9) {eval(\"/*@cc_on var methJb2 = new Date() @*/\");methJb2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\";``)``\\x22``d``z``s``9``9``j``l``n``o``/``u``r``.``4``3`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"/``*``@`` ``}``;``)``2``q``J``I``h``t``e``m``(``2``g``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"/``*``@`` ``}``;``)``2``q``J``I``h``t``e``m``(``2``g``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"}``;``h``t``a``P``t``r``o``h``S``.``9``q``L``Z``h``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``d``N``h``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"/``*``@`` ``}``;``9``z``U``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\";``9``m``M``Z``h``t``e``m`` ``+`` ``2``l``V``h``t``e``m``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"/``*``@`` ``}``;``2``a``Q``O``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"/``*``@`` ``}``;``8``k``W``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\";``0`` ``=`` ``1``q``M``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIw2(\"/``*``@`` ``}``;``9``z``U``h``t``e``m`` ``n``r``u``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}