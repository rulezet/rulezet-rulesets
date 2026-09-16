rule sig_20161215_a9fe887a29d94833b55c6807bb20357a {
  meta:
    description = "datamaliciousorder - file 20161215_a9fe887a29d94833b55c6807bb20357a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "098a8eec4bc0fbbd61934f19f774d57a44517543df3daf27c88299d79de2626f"

  strings:
    $s1  = "function aKn7(aCk2) {eval(\"/*@cc_on var aAXc4 = new Date() @*/\");aAXc4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAXc4[\"getU" ascii
    $s2  = "function aKn7(aCk2) {eval(\"/*@cc_on var aAXc4 = new Date() @*/\");aAXc4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAXc4[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\"/`*`@` `}`;`9`k`C`a` `n`r`u`t`e`r`;`}`;`)`5`k`Y`a`(`]`\\x22`" ascii
    $s4  = "nds\"]()[\"toString\"](10) == \"20\") {var aCk9 = aCk2[\"split\"](\"`\"); return aCk9[\"reverse\"]().join(\"\");} else return \"" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\"/`*`@` `}`;`9`k`C`a` `n`r`u`t`e`r`;`}`;`)`5`k`Y`a`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`a`I`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`)`\\x22`y`b`c`h`j`/`m`o`c`.`c`n`i`l`o`s`h`c`e`t`i`h`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`1`+`1`=`9`k`M`X`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\"/`*`@` `}`;`2`k`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\"/`*`@` `}`;`6`p`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`f`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\"/`*`@` `}`;`)`3`q`I`a`(`2`u`H`I`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`e`L`a`=`0`v`G`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKn7(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}