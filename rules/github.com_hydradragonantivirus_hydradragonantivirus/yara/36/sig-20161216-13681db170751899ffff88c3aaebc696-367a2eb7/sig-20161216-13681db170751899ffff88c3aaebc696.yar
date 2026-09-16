rule sig_20161216_13681db170751899ffff88c3aaebc696 {
  meta:
    description = "datamaliciousorder - file 20161216_13681db170751899ffff88c3aaebc696.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d13fcdbbdf4e1704f5b86761a27a3417c63e97e0bc3010623856d4a6a33e419d"

  strings:
    $s1  = "function methPv9(methUGr8) {eval(\"/*@cc_on var methOd1 = new Date() @*/\");methOd1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``t``I``h``t``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``5``h``Q``A``h``t``e``m`` ``+`` ``8``v``G``h``t``e``m``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"/``*``@`` ``}``;``8``r``G``U``h``t``e``m`` ``n``r``u``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"/``*``@`` ``}``;``8``r``G``U``h``t``e``m`` ``n``r``u``t``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"/``*``@`` ``}``;``5``a``M``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"/``*``@`` ``}``;``5``h``I``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"}``;``h``t``a``P``t``r``o``h``S``.``4``n``G``h``t``e``m``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``5``h``Q``A``h``t``e``m`` ``+`` ``8``v``G``h``t``e``m``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"}``;``h``t``a``P``t``r``o``h``S``.``4``n``G``h``t``e``m``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"/``*``@`` ``}``;``)``7``e``D``M``h``t``e``m``(``7``y``I``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``.`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``0`` ``=`` ``5``n``W``K``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPv9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}