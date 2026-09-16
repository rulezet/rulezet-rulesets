rule sig_20161216_0897c8a4bef6b2c4fea993a25839a1fb {
  meta:
    description = "datamaliciousorder - file 20161216_0897c8a4bef6b2c4fea993a25839a1fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca2435fb1e54c927aa061d1d554084d7800b9671b95bf39651c328a97c3534da"

  strings:
    $s1  = "function cheburgenDy2(cheburgenKWm7) {eval(\"/*@cc_on var cheburgenTa6 = new Date() @*/\");cheburgenTa6[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenTa6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenFDl8 = cheburgenKWm7[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\";``)``\\x22``\\x22`` ``+`` ``4``q``Y``n``e``g``r``u``b``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\";``0`` ``=`` ``3``o``Y``E``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\"/``*``@`` ``}``;``8``l``D``F``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``e``B``n``e``g``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\";``)``\\x22``\\x22`` ``+`` ``4``q``Y``n``e``g``r``u``b``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\"/``*``@`` ``}``;``7``m``W``K``n``e``g``r``u``b``e``h``c`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\";``2``x``M``n``e``g``r``u``b``e``h``c`` ``+`` ``6``e``A`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``e``B``n``e``g``r`" ascii
    $s16 = "function cheburgenDy2(cheburgenKWm7) {eval(\"/*@cc_on var cheburgenTa6 = new Date() @*/\");cheburgenTa6[\"setUTC\"+\"Seconds\"](" ascii
    $s17 = " cheburgenFDl8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\"/``*``@`` ``}``;``8``l``D``F``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\";``1``+``1``=``0``n``W``S``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``u``Z``n``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}