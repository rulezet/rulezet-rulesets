rule sig_20161215_930db1d109f1f2c681edc606e2defbf9 {
  meta:
    description = "datamaliciousorder - file 20161215_930db1d109f1f2c681edc606e2defbf9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8efd02631fbc98e39f41e2b1387e166f9d6fbdaa1c203849a5c62cec445244e8"

  strings:
    $s1  = "function aHKc0(aRb8) {eval(\"/*@cc_on var aDa8 = new Date() @*/\");aDa8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDa8[\"getUTC" ascii
    $s2  = "function aHKc0(aRb8) {eval(\"/*@cc_on var aDa8 = new Date() @*/\");aDa8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDa8[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`u`A`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`x`D`a`;`)`2` `,`1`x`E`K`a`(`]" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`k`N`P`a`=`1`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`1`+`1`=`8`n`C`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\"}`;`h`t`a`P`t`r`o`h`S`.`4`n`I`L`a` `n`r`u`t`e`r`;`)`1`v`S`E" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\"/`*`@` `}`;`3`o`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`u" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\"}`;`h`t`a`P`t`r`o`h`S`.`4`n`I`L`a` `n`r`u`t`e`r`;`)`1`v`S`E" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\"/`*`@` `}`;`8`b`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`\\x22`y`b`c`h`j`/`m`o`c`.`c`n`i`l`o`s`h`c`e`t`i`h`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`6`w`F`a` `+` `3`p`T`B`a`=`4`k`N`P`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHKc0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}