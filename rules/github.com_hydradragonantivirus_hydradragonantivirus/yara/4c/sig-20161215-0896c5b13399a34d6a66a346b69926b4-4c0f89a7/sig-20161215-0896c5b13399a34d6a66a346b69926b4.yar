rule sig_20161215_0896c5b13399a34d6a66a346b69926b4 {
  meta:
    description = "datamaliciousorder - file 20161215_0896c5b13399a34d6a66a346b69926b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cda02d412521aa63edf3b866d1eef63a9bb8aca8f866d4e064ae8c57ffe53aa"

  strings:
    $s1  = "function aEXi1(aDy0) {eval(\"/*@cc_on var aXa3 = new Date() @*/\");aXa3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXa3[\"getUTC" ascii
    $s2  = "function aEXi1(aDy0) {eval(\"/*@cc_on var aXa3 = new Date() @*/\");aXa3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXa3[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\"/`*`@` `}`;`)`0`c`X`a`(`5`g`R`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`1`r`A`C`a` `+` `3`f`A`a`=`8`e`A`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`v`C`U`a`;`)`2` `,`1`j`I`T`a`(" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`0` `=` `0`r`U`O`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\"}`;`h`t`a`P`t`r`o`h`S`.`8`y`W`a` `n`r`u`t`e`r`;`)`3`g`G`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\"/`*`@` `}`;`1`e`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`h" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\"/`*`@` `}`;`0`y`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`k`N`K`a` `r`a`v` `;" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEXi1(\"\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}