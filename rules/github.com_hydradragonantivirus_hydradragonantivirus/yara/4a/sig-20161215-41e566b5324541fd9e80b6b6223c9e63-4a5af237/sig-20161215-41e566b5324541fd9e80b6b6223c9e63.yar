rule sig_20161215_41e566b5324541fd9e80b6b6223c9e63 {
  meta:
    description = "datamaliciousorder - file 20161215_41e566b5324541fd9e80b6b6223c9e63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d038f3cfa9a137261e74e9ff627207fda1265f09a7a1bd24708af3af09758476"

  strings:
    $s1  = "function aEFk9(aHq1) {eval(\"/*@cc_on var aZf7 = new Date() @*/\");aZf7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZf7[\"getUTC" ascii
    $s2  = "function aEFk9(aHq1) {eval(\"/*@cc_on var aZf7 = new Date() @*/\");aZf7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZf7[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"/`*`@` `}`;`1`q`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"/`*`@` `}`;`5`v`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`b" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`)`\\x22`c`g`o`m`v`a`k`4`t`/`n`c`.`k`r`o`w`t`a`\\x22` `+` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"}`;`h`t`a`P`t`r`o`h`S`.`9`a`W`a` `n`r`u`t`e`r`;`)`0`g`D`a`(" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"}`;`h`t`a`P`t`r`o`h`S`.`9`a`W`a` `n`r`u`t`e`r`;`)`0`g`D`a`(" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"/`*`@` `}`;`6`f`R`T`a` `n`r`u`t`e`r`;`}`;`)`7`b`N`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`o`P`a` `r`a`v` ` ` ` \")), " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"/`*`@` `}`;`)`7`n`H`a`(`4`u`U`N`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`d`L`R`a`;`)`2` `,`1`s`B`H`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"/`*`@` `}`;`6`f`R`T`a` `n`r`u`t`e`r`;`}`;`)`7`b`N`a`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\"/`*`@` `}`;`)`7`n`H`a`(`4`u`U`N`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEFk9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}