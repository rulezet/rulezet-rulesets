rule sig_20161215_e209f8bd53af64eaf43b062aa6cfeeaa {
  meta:
    description = "datamaliciousorder - file 20161215_e209f8bd53af64eaf43b062aa6cfeeaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87224a44ce01b634092f146028256c94465103840e75b6f380f3d39e66443d52"

  strings:
    $s1  = "function aAw0(aBt6) {eval(\"/*@cc_on var aUTg4 = new Date() @*/\");aUTg4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUTg4[\"getU" ascii
    $s2  = "function aAw0(aBt6) {eval(\"/*@cc_on var aUTg4 = new Date() @*/\");aUTg4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUTg4[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` `" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`z`F`a`;`)`2` `,`5`g`B`W`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`x`M`a`=`0`w`H`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\"/`*`@` `}`;`8`p`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`w`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`j`F`P`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\"/`*`@` `}`;`)`7`q`W`a`(`8`n`K`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`j`F`P`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`g`Z`X`a` `r`a`v` ` ` ` \"))," ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAw0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}