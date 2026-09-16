rule sig_20161215_a3f50d47adf40f60a61c69a3d17d86b7 {
  meta:
    description = "datamaliciousorder - file 20161215_a3f50d47adf40f60a61c69a3d17d86b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c91824091a091f861a94c51cdb7e1bb18da0ae628f1d34d7919a1d2214228eb"

  strings:
    $s1  = "function aMs0(aVw9) {eval(\"/*@cc_on var aEMx6 = new Date() @*/\");aEMx6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEMx6[\"getU" ascii
    $s2  = "function aMs0(aVw9) {eval(\"/*@cc_on var aEMx6 = new Date() @*/\");aEMx6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEMx6[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\"/`*`@` `}`;`5`n`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`1`+`1`=`6`z`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`1`+`1`=`6`z`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`5`b`G`Q`a` `+` `5`f`Q`S`a`=`0`r`E`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`g`R`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\"/`*`@` `}`;`5`n`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`c`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`m`H`a` `n`r`u`t`e`r`;`)`3`b`G`B`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\"/`*`@` `}`;`)`0`q`X`a`(`9`s`I`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\"/`*`@` `}`;`9`w`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\"/`*`@` `}`;`)`0`q`X`a`(`9`s`I`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s19 = "nds\"]()[\"toString\"](10) == \"20\") {var aGs2 = aVw9[\"split\"](\"`\"); return aGs2[\"reverse\"]().join(\"\");} else return \"" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMs0(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `9`c`R`a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}