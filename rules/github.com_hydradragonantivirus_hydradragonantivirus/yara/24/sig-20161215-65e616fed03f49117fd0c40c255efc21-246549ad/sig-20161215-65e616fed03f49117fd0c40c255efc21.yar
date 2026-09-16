rule sig_20161215_65e616fed03f49117fd0c40c255efc21 {
  meta:
    description = "datamaliciousorder - file 20161215_65e616fed03f49117fd0c40c255efc21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a8b9c690fdbce9f1d818e92368b2d0fcc4b1b81daa2e0c075667e8e2edc275b"

  strings:
    $s1  = "function aJXh1(aIDw5) {eval(\"/*@cc_on var aVi0 = new Date() @*/\");aVi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVi0[\"getUT" ascii
    $s2  = "function aJXh1(aIDw5) {eval(\"/*@cc_on var aVi0 = new Date() @*/\");aVi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVi0[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\"/`*`@` `}`;`)`3`h`F`E`a`(`3`c`Q`T`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`1`+`1`=`4`l`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\"}`;`h`t`a`P`t`r`o`h`S`.`6`s`H`D`a` `n`r`u`t`e`r`;`)`9`q`I`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\"/`*`@` `}`;`5`w`D`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`y`C`a`;`)`2` `,`2`q`P`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\"/`*`@` `}`;`5`v`B`a` `n`r`u`t`e`r`;`}`;`)`1`m`Q`Q`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\"/`*`@` `}`;`5`r`N`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\"/`*`@` `}`;`5`v`B`a` `n`r`u`t`e`r`;`}`;`)`1`m`Q`Q`a`(`]`\\x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`8`n`S`I`a` `+` `9`x`N`a`=`2`u`P`H`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`u`P`H`a`=`9`q" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJXh1(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}