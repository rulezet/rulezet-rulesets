rule sig_20161215_4138f32cabb48bf84456a7d88e0cad32 {
  meta:
    description = "datamaliciousorder - file 20161215_4138f32cabb48bf84456a7d88e0cad32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1069544a37b9a7a3153b8605ba0c0d3ed29de024606d7968ef611f3d2c60543d"

  strings:
    $s1  = "function aLIg5(aNVy9) {eval(\"/*@cc_on var aPi7 = new Date() @*/\");aPi7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPi7[\"getUT" ascii
    $s2  = "function aLIg5(aNVy9) {eval(\"/*@cc_on var aPi7 = new Date() @*/\");aPi7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPi7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`w`O`a`=`6`x`U" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\"/`*`@` `}`;`)`3`r`Y`U`a`(`7`a`K`B`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\"}`;`h`t`a`P`t`r`o`h`S`.`7`g`K`a` `n`r`u`t`e`r`;`)`6`x`U`D`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`5`b`L`a` `+` `0`w`H`a`=`2`w`O`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`1`+`1`=`0`o`M`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\"/`*`@` `}`;`9`y`V`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`a`U`U`a` `r`a`v` ` ` ` \"))" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`v`w`h`2`8`/`m`o`c`.`g`f`s`u`m`a`n`i`d`\\x22` `+` " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`u`W`K`a` `r`a`v` `;" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLIg5(\"/`*`@` `}`;`)`3`r`Y`U`a`(`7`a`K`B`a` `n`r`u`t`e`r`;`)`(`e`s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}