rule sig_20161215_657aa87a348de1212e0b26382435e738 {
  meta:
    description = "datamaliciousorder - file 20161215_657aa87a348de1212e0b26382435e738.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f9da7dc55c01f7b7fd2d1d13756d76a8b6dd56a6ed18ec381a0af617f01d3de"

  strings:
    $s1  = "function aZOd2(aPc4) {eval(\"/*@cc_on var aTh1 = new Date() @*/\");aTh1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTh1[\"getUTC" ascii
    $s2  = "function aZOd2(aPc4) {eval(\"/*@cc_on var aTh1 = new Date() @*/\");aTh1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTh1[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\"/`*`@` `}`;`6`b`B`D`a` `n`r`u`t`e`r`;`}`;`)`3`j`K`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\"\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`1`+`1`=`9`x`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`h`L`a` `r`a`v` ` ` ` \")), " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`0` `=` `1`p`H`L`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`0`q`H`a` `+` `0`z`S`Q`a`=`3`n`D`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`n`D`a`=`4`m`M" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`w`L`E`a` `r`a`v` `;" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\"/`*`@` `}`;`8`c`K`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`g`E`Y`a`;`)`2` `,`0`j`V`G`a`(" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `2`r`H" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZOd2(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}