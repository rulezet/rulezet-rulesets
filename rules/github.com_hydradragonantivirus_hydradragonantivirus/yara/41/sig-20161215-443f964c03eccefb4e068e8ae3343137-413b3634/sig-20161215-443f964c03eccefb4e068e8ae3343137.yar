rule sig_20161215_443f964c03eccefb4e068e8ae3343137 {
  meta:
    description = "datamaliciousorder - file 20161215_443f964c03eccefb4e068e8ae3343137.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6b21e7b180ca27581085516d797d49f0d09fb4f97fe3ff89c0b2e8b884a625c"

  strings:
    $s1  = "function aSVk7(aWIk3) {eval(\"/*@cc_on var aRPu0 = new Date() @*/\");aRPu0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRPu0[\"ge" ascii
    $s2  = "function aSVk7(aWIk3) {eval(\"/*@cc_on var aRPu0 = new Date() @*/\");aRPu0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRPu0[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`1`+`1`=`1`g`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `6`k`B`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`f`X`a`=`2`m`E" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"}`;`h`t`a`P`t`r`o`h`S`.`8`a`P`a` `n`r`u`t`e`r`;`)`2`m`E`C`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"/`*`@` `}`;`)`6`r`G`a`(`2`s`J`U`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"/`*`@` `}`;`4`x`B`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"/`*`@` `}`;`3`u`Q`a` `n`r`u`t`e`r`;`}`;`)`1`j`S`Y`a`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`k`O`T`a` `r`a`v` `;" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`s`P`a`;`)`2` `,`4`p`O`L`a`(`]" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`)`\\x22`d`m`w`f`r`/`z`c`.`n`g`i`s`e`d`y`t`t`e`b`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `6`k`B`a" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\"/`*`@` `}`;`3`k`I`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVk7(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}