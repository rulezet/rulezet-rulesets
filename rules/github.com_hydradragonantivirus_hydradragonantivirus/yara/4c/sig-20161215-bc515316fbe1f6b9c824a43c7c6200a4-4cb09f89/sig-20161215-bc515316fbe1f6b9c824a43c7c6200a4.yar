rule sig_20161215_bc515316fbe1f6b9c824a43c7c6200a4 {
  meta:
    description = "datamaliciousorder - file 20161215_bc515316fbe1f6b9c824a43c7c6200a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf3f6244fd97b1090cee800403bd8db1b55f9c5db528f32a0bd79c801546e6ce"

  strings:
    $s1  = "function aHn9(aKVf2) {eval(\"/*@cc_on var aTDp6 = new Date() @*/\");aTDp6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTDp6[\"get" ascii
    $s2  = "function aHn9(aKVf2) {eval(\"/*@cc_on var aTDp6 = new Date() @*/\");aTDp6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTDp6[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`r`E`a`;`)`2` `,`3`u`F`J`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`1`+`1`=`7`n`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`p`T`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`1`z`S`a` `+` `5`s`M`a`=`7`h`Z`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`0` `=` `6`d`B`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`1`+`1`=`7`n`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s12 = "onds\"]()[\"toString\"](10) == \"20\") {var aJQk2 = aKVf2[\"split\"](\"`\"); return aJQk2[\"reverse\"]().join(\"\");} else retur" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` `" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`r`E`a`;`)`2` `,`3`u`F`J`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\"/`*`@` `}`;`2`f`V`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHn9(\"/`*`@` `}`;`2`k`Q`J`a` `n`r`u`t`e`r`;`}`;`)`1`i`K`K`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}