rule sig_20161215_f6b529340cd0ec02b8155d6b9fb129bd {
  meta:
    description = "datamaliciousorder - file 20161215_f6b529340cd0ec02b8155d6b9fb129bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9f1993c9eb1756dfca5bf8ff55aa2a415fe49adfba6e8356f8c3c4eabf4d37d"

  strings:
    $s1  = "function aZVc7(aSy4) {eval(\"/*@cc_on var aJm3 = new Date() @*/\");aJm3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJm3[\"getUTC" ascii
    $s2  = "function aZVc7(aSy4) {eval(\"/*@cc_on var aJm3 = new Date() @*/\");aJm3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJm3[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\"/`*`@` `}`;`0`y`L`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`d`W`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`d`B`V`a` `r`a`v` ` ` ` \"))" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `8" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`1`+`1`=`3`o`K`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`p`U`H`a`=`5`u" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\"/`*`@` `}`;`2`o`D`V`a` `n`r`u`t`e`r`;`}`;`)`4`l`H`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`p`U`H`a`=`5`u" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`y`C`a`;`)`2` `,`7`o`T`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\"/`*`@` `}`;`)`4`c`H`E`a`(`2`n`N`B`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZVc7(\";`0` `=` `7`v`O`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}