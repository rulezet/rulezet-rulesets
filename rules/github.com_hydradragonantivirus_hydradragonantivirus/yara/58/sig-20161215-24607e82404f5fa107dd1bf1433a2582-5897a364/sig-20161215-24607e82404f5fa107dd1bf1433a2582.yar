rule sig_20161215_24607e82404f5fa107dd1bf1433a2582 {
  meta:
    description = "datamaliciousorder - file 20161215_24607e82404f5fa107dd1bf1433a2582.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7040c096f7adadf24938eefee730b785221cf77aa79cd3aab8a3b89c40d5d02"

  strings:
    $s1  = "function aDj5(aABv6) {eval(\"/*@cc_on var aGt2 = new Date() @*/\");aGt2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGt2[\"getUTC" ascii
    $s2  = "function aDj5(aABv6) {eval(\"/*@cc_on var aGt2 = new Date() @*/\");aGt2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGt2[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`w`K`I`a` `n`r`u`t`e`r`;`)`8`a`E`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`1`+`1`=`1`r`Q`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\"/`*`@` `}`;`)`5`f`E`Z`a`(`4`k`D`T`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`4`h`P`H`a` `+` `5`s`S`a`=`8`m`M`Q`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `6`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`l`P`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`w`K`I`a` `n`r`u`t`e`r`;`)`8`a`E`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`m`M`Q`a`=`8`a`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` `" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\"/`*`@` `}`;`6`v`B`A`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDj5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`m`F`T`a`;`)`2` `,`6`w`X`K`a`(`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}