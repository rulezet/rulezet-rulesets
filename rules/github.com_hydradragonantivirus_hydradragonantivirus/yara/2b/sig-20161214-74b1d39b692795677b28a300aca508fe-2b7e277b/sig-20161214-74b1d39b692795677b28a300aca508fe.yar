rule sig_20161214_74b1d39b692795677b28a300aca508fe {
  meta:
    description = "datamaliciousorder - file 20161214_74b1d39b692795677b28a300aca508fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec4d41b8acf85e7e9c6d13885108dbd1709ffd8d1533b331eb45ca4799aceb09"

  strings:
    $s1  = "function aVOa9(aXq6) {eval(\"/*@cc_on var aHu9 = new Date() @*/\");aHu9[\"setUTCSeconds\"](\"0\", \"20\");if (aHu9.getUTCMillise" ascii
    $s2  = "function aVOa9(aXq6) {eval(\"/*@cc_on var aHu9 = new Date() @*/\");aHu9[\"setUTCSeconds\"](\"0\", \"20\");if (aHu9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\"/`*`@` `}`;`6`q`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`x`D`O`a` `r`a`v` ` ` ` \"))" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`1`+`1`=`2`c`C`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\"/`*`@` `}`;`)`9`w`V`D`a`(`4`c`W`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`h`I`T`a`;`)`2` `,`3`i`P`I`a`(" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`h`I`T`a`;`)`2` `,`3`i`P`I`a`(" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\"\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVOa9(\"/`*`@` `}`;`)`9`w`V`D`a`(`4`c`W`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}