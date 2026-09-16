rule sig_20161216_eb12db609f00bbc0ff80f59f41ecb065 {
  meta:
    description = "datamaliciousorder - file 20161216_eb12db609f00bbc0ff80f59f41ecb065.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48cc85580dc589e2d90f0666d715622455998322daddadf4b0d355ddc5ff8bdf"

  strings:
    $s1  = "\"20\");if (cheburgenFm0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenJe2 = cheburgenCQy2[\"split\"](\"`" ascii
    $s2  = "function cheburgenMYv4(cheburgenCQy2) {eval(\"/*@cc_on var cheburgenFm0 = new Date() @*/\");cheburgenFm0[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``f``Z``D``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\"/``*``@`` ``}``;``2``e``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``)``\\x22``\\x22`` ``+`` ``2``o``A``n``e``g``r``u``b`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``)``\\x22``\\x22`` ``+`` ``2``o``A``n``e``g``r``u``b`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``1``+``1``=``0``w``I``D``n``e``g``r``u``b``e``h``c`` " ascii
    $s10 = "function cheburgenMYv4(cheburgenCQy2) {eval(\"/*@cc_on var cheburgenFm0 = new Date() @*/\");cheburgenFm0[\"setUTC\"+\"Seconds\"]" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``f``Z``D``n" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``)``\\x22``d``g``l``i``l``x``x``a``/``e``d``.``g``n``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYv4(\";``0``g``A``A``n``e``g``r``u``b``e``h``c`` ``+`` ``8``i" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}