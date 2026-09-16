rule sig_20161215_699f1f3bff24eb46e1e5b023191e4f1c {
  meta:
    description = "datamaliciousorder - file 20161215_699f1f3bff24eb46e1e5b023191e4f1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "972476c1fbe102e1bf73610c178a55b948d650f1b5e5652ee33c17c1f3051060"

  strings:
    $s1  = "function aBUl0(aJCj6) {eval(\"/*@cc_on var aRi4 = new Date() @*/\");aRi4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRi4[\"getUT" ascii
    $s2  = "function aBUl0(aJCj6) {eval(\"/*@cc_on var aRi4 = new Date() @*/\");aRi4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRi4[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `3`c" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\"/`*`@` `}`;`6`t`Z`a` `n`r`u`t`e`r`;`}`;`)`4`u`G`a`(`]`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\"/`*`@` `}`;`6`j`C`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`1`+`1`=`8`d`Q`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `3" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`b`S`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\"/`*`@` `}`;`)`8`k`Q`T`a`(`2`w`W`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\"/`*`@` `}`;`6`j`C`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\"\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`5`i`V`a` `+` `4`y`W`V`a`=`5`e`H`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`1`+`1`=`8`d`Q`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `3" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBUl0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`f`T`I`a` `r`a`v` ` ` ` \"))" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}