rule sig_20161215_3cba3b489b55b6948af386be333059ae {
  meta:
    description = "datamaliciousorder - file 20161215_3cba3b489b55b6948af386be333059ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af00ea22838c728bd04a4aff79fe0676743bf102be63ac53666865544bb896c3"

  strings:
    $s1  = "function aJf7(aREt0) {eval(\"/*@cc_on var aPQu6 = new Date() @*/\");aPQu6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPQu6[\"get" ascii
    $s2  = "function aJf7(aREt0) {eval(\"/*@cc_on var aPQu6 = new Date() @*/\");aPQu6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPQu6[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"}`;`h`t`a`P`t`r`o`h`S`.`3`x`W`W`a` `n`r`u`t`e`r`;`)`0`v`R`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`)`\\x22`a`i`v`p`e`c`0`/`e`d`.`a`v`i`d`-`s`l`e`g`n`a`-`n`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` `" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`b`V`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`c`I`a`;`)`2` `,`4`l`K`Q`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`l`Y`O`a`=`0`v`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"/`*`@` `}`;`0`p`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`f`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"/`*`@` `}`;`1`g`Y`B`a` `n`r`u`t`e`r`;`}`;`)`2`m`V`Y`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`l`Y`O`a`=`0`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"/`*`@` `}`;`)`2`q`M`N`a`(`5`l`M`H`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`1`+`1`=`4`t`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"/`*`@` `}`;`0`t`E`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\"/`*`@` `}`;`0`p`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`f`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJf7(\";`)`\\x22`v`q`n`m`f`0`/`m`o`c`.`s`o`t`o`h`p`o`z`\\x22` `+` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}