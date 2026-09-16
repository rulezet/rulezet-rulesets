rule sig_20161214_6a8df0142b31f95f52fa704ba4b55413 {
  meta:
    description = "datamaliciousorder - file 20161214_6a8df0142b31f95f52fa704ba4b55413.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5acafa434dbec5bb27f78b59a1be964d87eb49faf32f9114fda35a1a1b0f523b"

  strings:
    $s1  = "function aKOl6(aMOg2) {eval(\"/*@cc_on var aPCk0 = new Date() @*/\");aPCk0[\"setUTCSeconds\"](\"0\", \"20\");if (aPCk0.getUTCMil" ascii
    $s2  = "function aKOl6(aMOg2) {eval(\"/*@cc_on var aPCk0 = new Date() @*/\");aPCk0[\"setUTCSeconds\"](\"0\", \"20\");if (aPCk0.getUTCMil" ascii
    $s3  = "s().toString(10) == \"20\") {var aFp7 = aMOg2[\"split\"](\"`\"); return aFp7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`1`+`1`=`8`n`F`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\"/`*`@` `}`;`7`p`F`a` `n`r`u`t`e`r`;`}`;`)`0`f`S`a`(`]`\\x22" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\"}`;`h`t`a`P`t`r`o`h`S`.`2`e`I`N`a` `n`r`u`t`e`r`;`)`7`h`Q`G" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\"/`*`@` `}`;`)`6`w`I`a`(`0`e`U`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\"/`*`@` `}`;`7`g`T`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\"/`*`@` `}`;`2`g`O`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\"/`*`@` `}`;`2`g`O`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\"\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKOl6(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}