rule sig_20161216_37a25867453c175afc3f4f93e87560c5 {
  meta:
    description = "datamaliciousorder - file 20161216_37a25867453c175afc3f4f93e87560c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2483a8aa98387c3f6000acfb7b4524935e2fe53e500f2fbeb230903e305a7fb1"

  strings:
    $s1  = "function methAYu7(methFYf2) {eval(\"/*@cc_on var methVp9 = new Date() @*/\");methVp9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"/``*``@`` ``}``;``)``0``n``J``h``t``e``m``(``2``z``W``Q`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"}``;``h``t``a``P``t``r``o``h``S``.``6``p``N``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"}``;``h``t``a``P``t``r``o``h``S``.``6``p``N``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"/``*``@`` ``}``;``1``p``X``U``h``t``e``m`` ``n``r``u``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``1``+``1``=``6``h``G``G``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``i``D``F`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"/``*``@`` ``}``;``1``m``O``Y``h``t``e``m`` ``n``r``u``t`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"/``*``@`` ``}``;``2``f``Y``F``h``t``e``m`` ``n``r``u``t`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\"/``*``@`` ``}``;``)``0``n``J``h``t``e``m``(``2``z``W``Q`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAYu7(\";``2``s``N``U``h``t``e``m`` ``+`` ``5``i``C``E``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}