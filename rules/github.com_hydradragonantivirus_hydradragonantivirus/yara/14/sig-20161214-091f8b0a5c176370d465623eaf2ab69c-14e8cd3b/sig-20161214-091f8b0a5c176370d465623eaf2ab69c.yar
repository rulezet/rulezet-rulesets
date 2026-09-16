rule sig_20161214_091f8b0a5c176370d465623eaf2ab69c {
  meta:
    description = "datamaliciousorder - file 20161214_091f8b0a5c176370d465623eaf2ab69c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4312b3c4eae5b2a05be24964fb94c76618cd4aa0c7dbddb4f5ad3cd150d0d9e"

  strings:
    $s1  = "function aCJf4(aKQy6) {eval(\"/*@cc_on var aLl1 = new Date() @*/\");aLl1[\"setUTCSeconds\"](\"0\", \"20\");if (aLl1.getUTCMillis" ascii
    $s2  = "function aCJf4(aKQy6) {eval(\"/*@cc_on var aLl1 = new Date() @*/\");aLl1[\"setUTCSeconds\"](\"0\", \"20\");if (aLl1.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`s`E`U`a`;`)`2` `,`5`p`S`U`a`(" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` " ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\"/`*`@` `}`;`)`4`n`T`a`(`6`z`M`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\"/`*`@` `}`;`)`4`n`T`a`(`6`z`M`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`v`Z`Y`a` `r`a`v` ` ` ` \"))" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` " ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`\\x22`d`w`n`h`3`c`m`/`m`o`c`.`i`a`i`d`u`w`\\x22` `+` `1" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\"/`*`@` `}`;`6`y`Q`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJf4(\"/`*`@` `}`;`6`s`V`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}