rule sig_20161215_95d7da24bb5f5f73a5d1a362d6bb3f9d {
  meta:
    description = "datamaliciousorder - file 20161215_95d7da24bb5f5f73a5d1a362d6bb3f9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77d716fcabd3e2425aba7ee5c3669d57252b5fea4daf86fe7449263bd7282caa"

  strings:
    $s1  = "function aGe3(aQCf1) {eval(\"/*@cc_on var aZCr7 = new Date() @*/\");aZCr7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZCr7[\"get" ascii
    $s2  = "function aGe3(aQCf1) {eval(\"/*@cc_on var aZCr7 = new Date() @*/\");aZCr7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZCr7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"/`*`@` `}`;`1`f`C`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"}`;`h`t`a`P`t`r`o`h`S`.`4`l`F`a` `n`r`u`t`e`r`;`)`6`c`W`a`(`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"/`*`@` `}`;`)`1`z`Q`a`(`8`x`M`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`d`L`G`a`;`)`2` `,`2`x`K`X`a`(`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"/`*`@` `}`;`4`a`C`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`j`Z`E`a`=`6`c`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"/`*`@` `}`;`)`1`z`Q`a`(`8`x`M`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"/`*`@` `}`;`6`a`N`a` `n`r`u`t`e`r`;`}`;`)`3`y`O`J`a`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `2`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`1`+`1`=`4`b`B`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`d`L`G`a`;`)`2` `,`2`x`K`X`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGe3(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `2`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}