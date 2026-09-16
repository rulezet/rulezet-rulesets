rule sig_20161215_d6788f7fce665bf2d08f6e5302ffbb77 {
  meta:
    description = "datamaliciousorder - file 20161215_d6788f7fce665bf2d08f6e5302ffbb77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ccf414b4086907755633e6b5f2d9d641e13f561a8bcae9796579e7ba0aedf8d"

  strings:
    $s1  = "function aYBc8(aJu1) {eval(\"/*@cc_on var aHx9 = new Date() @*/\");aHx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHx9[\"getUTC" ascii
    $s2  = "function aYBc8(aJu1) {eval(\"/*@cc_on var aHx9 = new Date() @*/\");aHx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHx9[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`e`K`C`a` `r`a`v` ` ` ` \"))" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\"/`*`@` `}`;`9`z`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`a" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`a`E`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\"/`*`@` `}`;`1`u`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\"}`;`h`t`a`P`t`r`o`h`S`.`2`t`U`a` `n`r`u`t`e`r`;`)`8`v`W`S`a" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`m`X`A`a`;`)`2` `,`7`t`L`a`(`]" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\"/`*`@` `}`;`7`m`K`D`a` `n`r`u`t`e`r`;`}`;`)`2`l`X`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\"/`*`@` `}`;`9`z`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`)`\\x22`v`q`n`m`f`0`/`m`o`c`.`s`o`t`o`h`p`o`z`\\x22` `+` " ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`)`\\x22`a`i`v`p`e`c`0`/`e`d`.`a`v`i`d`-`s`l`e`g`n`a`-`n`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`j`Q`B`a`=`8`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`1`+`1`=`4`u`F`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\"}`;`h`t`a`P`t`r`o`h`S`.`2`t`U`a` `n`r`u`t`e`r`;`)`8`v`W`S`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBc8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}