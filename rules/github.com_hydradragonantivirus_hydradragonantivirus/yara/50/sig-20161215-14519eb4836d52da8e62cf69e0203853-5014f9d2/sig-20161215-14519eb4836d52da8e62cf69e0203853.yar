rule sig_20161215_14519eb4836d52da8e62cf69e0203853 {
  meta:
    description = "datamaliciousorder - file 20161215_14519eb4836d52da8e62cf69e0203853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "811360c0668b5c11f682f870fcc54bb7d6d14c6765afa6eeaaf929c09c3ab3dd"

  strings:
    $s1  = "function cheburgenBLg3(cheburgenPj2) {eval(\"/*@cc_on var cheburgenBb7 = new Date() @*/\");cheburgenBb7[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenBb7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenFx7 = cheburgenPj2[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s4  = "heburgenFx7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\"/``*``@`` ``}``;``3``f``E``L``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``0`` ``=`` ``6``w``E``Z``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``0`` ``=`` ``6``w``E``Z``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``u``F``N``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\"/``*``@`` ``}``;``)``3``b``K``X``n``e``g``r``u``b``e``h" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\"/``*``@`` ``}``;``7``x``F``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``1``+``1``=``6``d``X``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``h``W``C" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``h``W``C" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBLg3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}