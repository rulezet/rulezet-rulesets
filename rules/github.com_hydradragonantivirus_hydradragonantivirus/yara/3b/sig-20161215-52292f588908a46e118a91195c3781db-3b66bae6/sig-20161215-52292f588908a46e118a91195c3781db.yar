rule sig_20161215_52292f588908a46e118a91195c3781db {
  meta:
    description = "datamaliciousorder - file 20161215_52292f588908a46e118a91195c3781db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f65f7f4eb9d6fcd185b899fb262620dde7581bbbf64e0179e8b604cb2763bae7"

  strings:
    $s1  = "function cheburgenTGa7(cheburgenKIz0) {eval(\"/*@cc_on var cheburgenLl8 = new Date() @*/\");cheburgenLl8[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenLl8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenVb8 = cheburgenKIz0[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\"}``;``h``t``a``P``t``r``o``h``S``.``6``g``U``D``n``e``g" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\"\")), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``a``E``Y" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\"/``*``@`` ``}``;``1``j``D``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\"/``*``@`` ``}``;``)``1``y``L``n``e``g``r``u``b``e``h``c" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``)``\\x22``\\x22`` ``+`` ``8``e``G``X``n``e``g``r``u`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\"}``;``h``t``a``P``t``r``o``h``S``.``6``g``U``D``n``e``g" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\"/``*``@`` ``}``;``8``b``V``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``1``+``1``=``9``s``Y``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``0``d``D``n``e``g``r``u``b``e``h``c`` ``+`` ``5``i``A" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``0`` ``=`` ``9``t``H``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``)``\\x22``\\x22`` ``+`` ``8``e``G``X``n``e``g``r``u`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTGa7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}