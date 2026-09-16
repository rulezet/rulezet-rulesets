rule sig_20161214_bbd87ed5349d0619978f3ba20195f3c0 {
  meta:
    description = "datamaliciousorder - file 20161214_bbd87ed5349d0619978f3ba20195f3c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9da0537d054e86bea0ebc6e3bc2e05e0f8e9c86c669f1cbe8c9d83272e13e65"

  strings:
    $s1  = "function aFBf4(aCo4) {eval(\"/*@cc_on var aDh5 = new Date() @*/\");aDh5[\"setUTCSeconds\"](\"0\", \"20\");if (aDh5.getUTCMillise" ascii
    $s2  = "function aFBf4(aCo4) {eval(\"/*@cc_on var aDh5 = new Date() @*/\");aDh5[\"setUTCSeconds\"](\"0\", \"20\");if (aDh5.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`1`+`1`=`1`o`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\"/`*`@` `}`;`)`9`o`Z`X`a`(`8`p`G`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\"/`*`@` `}`;`8`m`C`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`1`+`1`=`1`o`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `0`n`V`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`s`X`E`a`;`)`2` `,`9`v`A`a`(`]" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`v`O`a` `r`a`v` ` ` ` \")), " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`w`T`a` `n`r`u`t`e`r`;`)`8`q`L`Y`a" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\"\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\"/`*`@` `}`;`4`o`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`x`T`I`a`=`8`q" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFBf4(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}