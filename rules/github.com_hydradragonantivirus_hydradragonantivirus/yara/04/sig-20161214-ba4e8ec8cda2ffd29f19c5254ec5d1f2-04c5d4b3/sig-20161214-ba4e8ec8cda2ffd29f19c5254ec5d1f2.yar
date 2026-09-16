rule sig_20161214_ba4e8ec8cda2ffd29f19c5254ec5d1f2 {
  meta:
    description = "datamaliciousorder - file 20161214_ba4e8ec8cda2ffd29f19c5254ec5d1f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d941c245d786dff0aca47144c76ad050d372247a393cb6a78ff1c235645b73c0"

  strings:
    $s1  = "function aQFj7(aEl2) {eval(\"/*@cc_on var aGAu5 = new Date() @*/\");aGAu5[\"setUTCSeconds\"](\"0\", \"20\");if (aGAu5.getUTCMill" ascii
    $s2  = "function aQFj7(aEl2) {eval(\"/*@cc_on var aGAu5 = new Date() @*/\");aGAu5[\"setUTCSeconds\"](\"0\", \"20\");if (aGAu5.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`1`+`1`=`6`g`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`a`C`M`a` `r`a`v` ` ` ` \"))" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`9`e`U`L`a` `+` `2`i`A`X`a`=`6`l`I`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `3`e`T" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`0` `=` `7`p`Z`J`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`l`I`a`=`5`w`K" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`i`K`J`a`;`)`2` `,`8`x`Y`A`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `3`e`T" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQFj7(\"/`*`@` `}`;`8`h`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`b" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}