rule sig_20161216_43527b611a1d483582f2f5b76126f633 {
  meta:
    description = "datamaliciousorder - file 20161216_43527b611a1d483582f2f5b76126f633.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00831c88f43c8ffb980e455322349381eb288a7aecfc9b7cff9ed948928f08bf"

  strings:
    $s1  = "function cheburgenUVv3(cheburgenYEm8) {eval(\"/*@cc_on var cheburgenUBe8 = new Date() @*/\");cheburgenUBe8[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\"/``*``@`` ``}``;``0``b``C``n``e``g``r``u``b``e``h``c`` " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``7``p``O``n``e``g``r``u``b``e``h``c`` ``+`` ``9``z``O" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``h``X``C``n``e``g" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\"/``*``@`` ``}``;``0``b``C``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``w``F``V``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``l``F``n" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``)``\\x22``\\x22`` ``+`` ``5``f``B``n``e``g``r``u``b`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``)``\\x22``\\x22`` ``+`` ``5``f``B``n``e``g``r``u``b`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``7``p``O``n``e``g``r``u``b``e``h``c`` ``+`` ``9``z``O" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\"/``*``@`` ``}``;``)``0``d``U``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\"/``*``@`` ``}``;``5``g``C``H``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUVv3(\";``0`` ``=`` ``9``p``S``n``e``g``r``u``b``e``h``c`` ``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}