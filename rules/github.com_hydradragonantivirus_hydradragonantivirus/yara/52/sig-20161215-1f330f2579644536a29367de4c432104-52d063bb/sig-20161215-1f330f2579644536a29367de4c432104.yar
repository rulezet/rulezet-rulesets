rule sig_20161215_1f330f2579644536a29367de4c432104 {
  meta:
    description = "datamaliciousorder - file 20161215_1f330f2579644536a29367de4c432104.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3af3c88535aa68a54e469fafa57a212b2c9475821aadcb30c735e447683daae8"

  strings:
    $s1  = "function aHi6(aHJq9) {eval(\"/*@cc_on var aWn7 = new Date() @*/\");aWn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWn7[\"getUTC" ascii
    $s2  = "function aHi6(aHJq9) {eval(\"/*@cc_on var aWn7 = new Date() @*/\");aWn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWn7[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\"/`*`@` `}`;`2`e`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`e`L`a`;`)`2` `,`5`t`M`J`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`0` `=` `3`q`K`M`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`1`+`1`=`7`d`Q`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`)`\\x22`c`g`o`m`v`a`k`4`t`/`n`c`.`k`r`o`w`t`a`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\"/`*`@` `}`;`)`8`y`O`a`(`5`t`A`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\"/`*`@` `}`;`9`q`J`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\"/`*`@` `}`;`2`e`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`e`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`7`r`L`S`a` `+` `8`f`X`B`a`=`4`m`B`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi6(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}