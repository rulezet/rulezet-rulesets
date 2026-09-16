rule sig_20161216_0bb1a2a9c39e07150298adac185478cf {
  meta:
    description = "datamaliciousorder - file 20161216_0bb1a2a9c39e07150298adac185478cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "646bd9cd665e5df1be11aa77dd75b15636b993924aa3d93d1aaceabb8b9c3171"

  strings:
    $s1  = "function cheburgenDVr2(cheburgenAh5) {eval(\"/*@cc_on var cheburgenEm4 = new Date() @*/\");cheburgenEm4[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenEm4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenZh7 = cheburgenAh5[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``p``V``n``e" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\"/``*``@`` ``}``;``5``h``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``i``N``T" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\"\")), 1);//////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\"/``*``@`` ``}``;``7``h``Z``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\"/``*``@`` ``}``;``5``y``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "function cheburgenDVr2(cheburgenAh5) {eval(\"/*@cc_on var cheburgenEm4 = new Date() @*/\");cheburgenEm4[\"setUTC\"+\"Seconds\"](" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``g``E``F``n``e``g" ascii
    $s17 = "heburgenZh7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``)``\\x22``\\x22`` ``+`` ``0``f``L``F``n``e``g``r``u`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDVr2(\";``)``\\x22``g``k``q``0``4``n``w``3``/``u``r``.``o``n``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}