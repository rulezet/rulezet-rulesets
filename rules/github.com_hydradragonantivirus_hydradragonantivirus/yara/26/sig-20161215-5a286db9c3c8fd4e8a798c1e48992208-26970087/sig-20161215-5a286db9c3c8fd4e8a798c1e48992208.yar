rule sig_20161215_5a286db9c3c8fd4e8a798c1e48992208 {
  meta:
    description = "datamaliciousorder - file 20161215_5a286db9c3c8fd4e8a798c1e48992208.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d75c6b2fade6382745b478501dfc9caa0ab3f3d2fbec187508c6a8303c9089f"

  strings:
    $s1  = "function aSm1(aIj5) {eval(\"/*@cc_on var aSi7 = new Date() @*/\");aSi7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSi7[\"getUTCM" ascii
    $s2  = "function aSm1(aIj5) {eval(\"/*@cc_on var aSi7 = new Date() @*/\");aSi7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSi7[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`n`M`F`a`;`)`2` `,`1`t`S`Q`a`(`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`1`+`1`=`6`p`L`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`o`U`a` `r`a`v` `;`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\"/`*`@` `}`;`5`j`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\"}`;`h`t`a`P`t`r`o`h`S`.`4`i`F`W`a` `n`r`u`t`e`r`;`)`5`p`C`a`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`n`M`F`a`;`)`2` `,`1`t`S`Q`a`(`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\"/`*`@` `}`;`0`i`P`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`1`+`1`=`6`p`L`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`0` `=` `4`y`W`V`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`c`E`K`a`=`5`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`)`\\x22`x`x`1`p`l`e`n`v`d`/`m`o`c`.`t`s`s`e`w`-`a`d`n`a`f`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`o`U`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\"/`*`@` `}`;`2`t`B`a` `n`r`u`t`e`r`;`}`;`)`1`c`Z`a`(`]`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSm1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}