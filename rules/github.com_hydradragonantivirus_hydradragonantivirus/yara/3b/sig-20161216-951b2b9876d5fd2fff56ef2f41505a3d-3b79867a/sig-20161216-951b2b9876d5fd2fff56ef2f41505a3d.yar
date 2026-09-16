rule sig_20161216_951b2b9876d5fd2fff56ef2f41505a3d {
  meta:
    description = "datamaliciousorder - file 20161216_951b2b9876d5fd2fff56ef2f41505a3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0832937b4d8b386acc523983ddb7e62870394e43c09db33f2f959526a16d53f4"

  strings:
    $s1  = "function cheburgenAEc3(cheburgenKDq7) {eval(\"/*@cc_on var cheburgenUWu3 = new Date() @*/\");cheburgenUWu3[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``i``K``n" ascii
    $s3  = "function cheburgenAEc3(cheburgenKDq7) {eval(\"/*@cc_on var cheburgenUWu3 = new Date() @*/\");cheburgenUWu3[\"setUTC\"+\"Seconds" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``z``I``K``n" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``)``\\x22``\\x22`` ``+`` ``3``y``H``n``e``g``r``u``b`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\"/``*``@`` ``}``;``7``q``D``K``n``e``g``r``u``b``e``h``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``2``y``G``n``e``g``r``u``b``e``h``c`` ``+`` ``5``p``Y" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\"/``*``@`` ``}``;``)``5``k``F``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``)``\\x22``\\x22`` ``+`` ``3``y``H``n``e``g``r``u``b`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``0`` ``=`` ``1``o``W``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\"/``*``@`` ``}``;``7``q``D``K``n``e``g``r``u``b``e``h``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\"/``*``@`` ``}``;``8``r``F``N``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAEc3(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}