rule sig_20161214_364b8b9bb0291684d068c27ed4774a27 {
  meta:
    description = "datamaliciousorder - file 20161214_364b8b9bb0291684d068c27ed4774a27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ad9acdff0d07313d7fe527d19de7f3dcab7d5e12053850919258a67703670db"

  strings:
    $s1  = "function aFVp7(aCb4) {eval(\"/*@cc_on var aJPb0 = new Date() @*/\");aJPb0[\"setUTCSeconds\"](\"0\", \"20\");if (aJPb0.getUTCMill" ascii
    $s2  = "function aFVp7(aCb4) {eval(\"/*@cc_on var aJPb0 = new Date() @*/\");aJPb0[\"setUTCSeconds\"](\"0\", \"20\");if (aJPb0.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\"/`*`@` `}`;`4`u`S`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\"/`*`@` `}`;`4`u`S`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\"}`;`h`t`a`P`t`r`o`h`S`.`4`c`L`a` `n`r`u`t`e`r`;`)`6`j`G`W`a" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`n`N`a` `r`a`v` ` ` ` \")), " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`l`D`A`a`=`6`j" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`1`+`1`=`1`n`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `1`o`E" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`y`D`a`;`)`2` `,`6`r`A`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\"/`*`@` `}`;`)`2`j`Q`a`(`4`f`K`Y`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFVp7(\";`7`u`G`M`a` `+` `0`o`Q`a`=`2`l`D`A`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}