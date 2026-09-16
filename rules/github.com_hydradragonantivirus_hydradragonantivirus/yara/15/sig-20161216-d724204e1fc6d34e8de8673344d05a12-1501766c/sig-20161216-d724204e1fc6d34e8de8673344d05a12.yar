rule sig_20161216_d724204e1fc6d34e8de8673344d05a12 {
  meta:
    description = "datamaliciousorder - file 20161216_d724204e1fc6d34e8de8673344d05a12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ab9ae0be2c7550dabb5eb812e69fe87e5f6c38035901862973a9b7a9e972e42"

  strings:
    $s1  = "function cheburgenNk5(cheburgenVs6) {eval(\"/*@cc_on var cheburgenEh1 = new Date() @*/\");cheburgenEh1[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenEh1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenRAy2 = cheburgenVs6[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``)``\\x22``\\x22`` ``+`` ``9``s``Q``n``e``g``r``u``b``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\"/``*``@`` ``}``;``2``y``A``R``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``)``\\x22``\\x22`` ``+`` ``9``s``Q``n``e``g``r``u``b``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``i" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\"\")), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``)``\\x22``6``g``c``g``6``/``e``d``.``c``i``s``u``m``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``0`` ``=`` ``0``m``W``B``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\"/``*``@`` ``}``;``6``s``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``0`` ``=`` ``0``m``W``B``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\"/``*``@`` ``}``;``)``0``k``K``V``n``e``g``r``u``b``e``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``t" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``s``C``n`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNk5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}