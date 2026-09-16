rule sig_20161215_35d01824e835c487c2923e367d4b2cfe {
  meta:
    description = "datamaliciousorder - file 20161215_35d01824e835c487c2923e367d4b2cfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6039a71f6662ed8b55e67cb587e8a769ce1737a71cee9462296d90f9248898e"

  strings:
    $s1  = "function aBg1(aBh8) {eval(\"/*@cc_on var aCFv5 = new Date() @*/\");aCFv5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCFv5[\"getU" ascii
    $s2  = "function aBg1(aBh8) {eval(\"/*@cc_on var aCFv5 = new Date() @*/\");aCFv5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCFv5[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`1`+`1`=`2`o`Z`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\"}`;`h`t`a`P`t`r`o`h`S`.`7`c`T`a` `n`r`u`t`e`r`;`)`7`u`S`B`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`s`Q`U`a`=`7`u`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`l`R`A`a`;`)`2` `,`0`i`M`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`1`w`G`a` `+` `9`u`D`a`=`5`s`Q`U`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\"/`*`@` `}`;`)`5`q`K`U`a`(`0`s`F`A`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\"/`*`@` `}`;`)`5`q`K`U`a`(`0`s`F`A`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`k`Q`W`a` `r`a`v` `;`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`)`\\x22`l`y`k`0`o`n`r`t`c`i`/`m`o`c`.`s`r`e`i`r`r`e`t`x`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\"/`*`@` `}`;`9`c`V`a` `n`r`u`t`e`r`;`}`;`)`0`m`A`a`(`]`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\";`0` `=` `8`g`S`R`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBg1(\"\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}