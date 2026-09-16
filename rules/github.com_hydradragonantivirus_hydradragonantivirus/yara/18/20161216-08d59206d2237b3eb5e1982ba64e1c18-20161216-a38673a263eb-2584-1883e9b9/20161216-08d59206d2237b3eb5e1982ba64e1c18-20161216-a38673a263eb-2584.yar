rule _20161216_08d59206d2237b3eb5e1982ba64e1c18_20161216_a38673a263eb_2584 {
  meta:
    description = "datamaliciousorder - from files 20161216_08d59206d2237b3eb5e1982ba64e1c18.js, 20161216_a38673a263eb26dec7a6858fc3f61bf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1c61e9e743aebffeb15112f30c913f4df9ccbe3d97ff85e1c8b2eaebe1a9350"
    hash2       = "bc7dd42c81b70fbba8fc3152e5cd49df10eb382c2d0e95e7a4228701052bb493"

  strings:
    $s1 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEe2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s2 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEe2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s3 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEe2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEe2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s5 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEe2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s6 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEe2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s7 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEe2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s8 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEe2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}