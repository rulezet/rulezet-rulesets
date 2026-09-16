rule sig_20161215_16322d78f2c32015f1376ac07173932c {
  meta:
    description = "datamaliciousorder - file 20161215_16322d78f2c32015f1376ac07173932c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a9d3cb5fe093c9c156c35c657505c98867f1ee7b59ab4f50fcd34c49930f7e9"

  strings:
    $s1  = "function aPUe2(aMSv8) {eval(\"/*@cc_on var aVRn2 = new Date() @*/\");aVRn2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVRn2[\"ge" ascii
    $s2  = "function aPUe2(aMSv8) {eval(\"/*@cc_on var aVRn2 = new Date() @*/\");aVRn2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVRn2[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\"/`*`@` `}`;`)`9`s`P`L`a`(`8`l`V`Z`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\"}`;`h`t`a`P`t`r`o`h`S`.`3`i`O`R`a` `n`r`u`t`e`r`;`)`3`h`A`a" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`u`K`a` `r`a`v` `;`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`u`K`a` `r`a`v` `;`" ascii
    $s11 = "conds\"]()[\"toString\"](10) == \"20\") {var aYXd6 = aMSv8[\"split\"](\"`\"); return aYXd6[\"reverse\"]().join(\"\");} else retu" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\"/`*`@` `}`;`8`v`S`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\"/`*`@` `}`;`6`d`X`Y`a` `n`r`u`t`e`r`;`}`;`)`4`z`Q`Z`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\"/`*`@` `}`;`)`9`s`P`L`a`(`8`l`V`Z`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`5`d`L`a` `+` `9`w`L`Y`a`=`6`a`Y`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\"/`*`@` `}`;`6`d`X`Y`a` `n`r`u`t`e`r`;`}`;`)`4`z`Q`Z`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`1`+`1`=`4`f`Y`X`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUe2(\";`)`\\x22`v`w`h`2`8`/`m`o`c`.`g`f`s`u`m`a`n`i`d`\\x22` `+` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}