rule sig_20161214_21d97cf15afddc8ccdbc7c6d61fc84e4 {
  meta:
    description = "datamaliciousorder - file 20161214_21d97cf15afddc8ccdbc7c6d61fc84e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6173c31e4e60c95b8630a867ed87e8e2e15f8837ab70695e774c47ad04c1a2fe"

  strings:
    $s1  = "function aROr1(aLNd7) {eval(\"/*@cc_on var aZSc1 = new Date() @*/\");aZSc1[\"setUTCSeconds\"](\"0\", \"20\");if (aZSc1.getUTCMil" ascii
    $s2  = "function aROr1(aLNd7) {eval(\"/*@cc_on var aZSc1 = new Date() @*/\");aZSc1[\"setUTCSeconds\"](\"0\", \"20\");if (aZSc1.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`h`Q`Y`a`;`)`2` `,`6`s`H`a`(`]" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"}`;`h`t`a`P`t`r`o`h`S`.`8`k`Q`F`a` `n`r`u`t`e`r`;`)`5`n`P`a" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"/`*`@` `}`;`)`7`t`B`a`(`3`k`D`I`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"/`*`@` `}`;`8`k`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`r" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"/`*`@` `}`;`8`j`V`a` `n`r`u`t`e`r`;`}`;`)`0`x`J`a`(`]`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"/`*`@` `}`;`7`d`N`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"/`*`@` `}`;`)`7`t`B`a`(`3`k`D`I`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`x`G`a`=`5`n`P" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\"}`;`h`t`a`P`t`r`o`h`S`.`8`k`Q`F`a` `n`r`u`t`e`r`;`)`5`n`P`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aROr1(\";`1`+`1`=`9`j`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}