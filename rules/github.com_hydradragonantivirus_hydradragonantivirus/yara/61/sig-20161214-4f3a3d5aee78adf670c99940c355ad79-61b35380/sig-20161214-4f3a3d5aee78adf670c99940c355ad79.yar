rule sig_20161214_4f3a3d5aee78adf670c99940c355ad79 {
  meta:
    description = "datamaliciousorder - file 20161214_4f3a3d5aee78adf670c99940c355ad79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ace8f16f65de9df2a1e063e2c5114ee5116f08aebba64123d94dc130e976fd3b"

  strings:
    $s1  = "function aQy9(aGj8) {eval(\"/*@cc_on var aKRc8 = new Date() @*/\");aKRc8[\"setUTCSeconds\"](\"0\", \"20\");if (aKRc8.getUTCMilli" ascii
    $s2  = "function aQy9(aGj8) {eval(\"/*@cc_on var aKRc8 = new Date() @*/\");aKRc8[\"setUTCSeconds\"](\"0\", \"20\");if (aKRc8.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\"/`*`@` `}`;`)`7`x`C`F`a`(`1`v`I`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `0`j`T`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`1`+`1`=`2`n`X`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `0`j`T`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`3`l`V`D`a` `+` `8`f`B`D`a`=`2`k`L`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`1`+`1`=`2`n`X`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\"/`*`@` `}`;`8`j`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\"/`*`@` `}`;`7`p`L`a` `n`r`u`t`e`r`;`}`;`)`0`y`T`a`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\"/`*`@` `}`;`9`d`F`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `0`j`T`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\"}`;`h`t`a`P`t`r`o`h`S`.`2`y`G`T`a` `n`r`u`t`e`r`;`)`8`w`W`P`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy9(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+`" ascii
    $s20 = ").toString(10) == \"20\") {var aLp7 = aGj8[\"split\"](\"`\"); return aLp7.reverse().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}