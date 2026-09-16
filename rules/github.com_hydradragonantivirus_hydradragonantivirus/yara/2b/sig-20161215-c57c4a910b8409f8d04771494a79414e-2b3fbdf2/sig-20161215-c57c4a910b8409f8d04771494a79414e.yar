rule sig_20161215_c57c4a910b8409f8d04771494a79414e {
  meta:
    description = "datamaliciousorder - file 20161215_c57c4a910b8409f8d04771494a79414e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "570cf1474684c319a00c6c4c2030d47cc94e5093732ecca576c73589d739a87c"

  strings:
    $s1  = "function aPl9(aNa7) {eval(\"/*@cc_on var aPPz6 = new Date() @*/\");aPPz6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPPz6[\"getU" ascii
    $s2  = "function aPl9(aNa7) {eval(\"/*@cc_on var aPPz6 = new Date() @*/\");aPPz6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPPz6[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `6`q`L`R`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`d`O`O`a` `r`a`v` `;`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\"/`*`@` `}`;`9`p`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\"/`*`@` `}`;`)`0`z`I`N`a`(`8`f`F`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`)`\\x22`1`t`j`m`g`a`3`/`m`o`c`.`b`l`-`e`c`i`f`f`o`r`e`t`n`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`1`+`1`=`7`q`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`0`q`L`V`a` `+` `1`s`F`W`a`=`4`a`H`O`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\"}`;`h`t`a`P`t`r`o`h`S`.`3`s`L`a` `n`r`u`t`e`r`;`)`8`n`J`a`(`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`x`T`a`;`)`2` `,`2`w`N`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\"}`;`h`t`a`P`t`r`o`h`S`.`3`s`L`a` `n`r`u`t`e`r`;`)`8`n`J`a`(`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`a`H`O`a`=`8`n`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPl9(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}