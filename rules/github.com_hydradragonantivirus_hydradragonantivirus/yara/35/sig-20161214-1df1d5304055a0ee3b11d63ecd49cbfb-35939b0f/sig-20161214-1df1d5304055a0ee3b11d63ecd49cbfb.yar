rule sig_20161214_1df1d5304055a0ee3b11d63ecd49cbfb {
  meta:
    description = "datamaliciousorder - file 20161214_1df1d5304055a0ee3b11d63ecd49cbfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c6c5e2b47a68af4e526527e3df181592bb8d576bb5bf598bab9baa1dadadaf5"

  strings:
    $s1  = "function aKCl2(aQt0) {eval(\"/*@cc_on var aLZv8 = new Date() @*/\");aLZv8[\"setUTCSeconds\"](\"0\", \"20\");if (aLZv8.getUTCMill" ascii
    $s2  = "function aKCl2(aQt0) {eval(\"/*@cc_on var aLZv8 = new Date() @*/\");aLZv8[\"setUTCSeconds\"](\"0\", \"20\");if (aLZv8.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`i`V`a`=`9`h`M" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\"/`*`@` `}`;`)`5`p`Y`a`(`7`m`V`U`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\"/`*`@` `}`;`)`5`p`Y`a`(`7`m`V`U`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\"/`*`@` `}`;`0`t`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\"/`*`@` `}`;`6`h`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`h" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`r`X`a`;`)`2` `,`5`o`J`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\";`1`+`1`=`4`x`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKCl2(\"}`;`h`t`a`P`t`r`o`h`S`.`4`h`P`B`a` `n`r`u`t`e`r`;`)`9`h`M`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}