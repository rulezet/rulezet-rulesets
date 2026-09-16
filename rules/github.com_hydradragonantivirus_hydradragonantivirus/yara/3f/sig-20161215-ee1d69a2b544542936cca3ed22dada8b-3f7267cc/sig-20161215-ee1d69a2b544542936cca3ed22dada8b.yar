rule sig_20161215_ee1d69a2b544542936cca3ed22dada8b {
  meta:
    description = "datamaliciousorder - file 20161215_ee1d69a2b544542936cca3ed22dada8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17568e06b3229a45e6f42592a50fbe951b07bed0e2871facd11685948f474c23"

  strings:
    $s1  = "function aQVl2(aVCa9) {eval(\"/*@cc_on var aFWs3 = new Date() @*/\");aFWs3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFWs3[\"ge" ascii
    $s2  = "function aQVl2(aVCa9) {eval(\"/*@cc_on var aFWs3 = new Date() @*/\");aFWs3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFWs3[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\"/`*`@` `}`;`8`o`P`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\"/`*`@` `}`;`0`a`H`X`a` `n`r`u`t`e`r`;`}`;`)`7`v`L`a`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`u`G`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\"/`*`@` `}`;`9`a`C`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`9`w`C`a` `+` `8`g`Z`a`=`7`p`K`Y`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`b`T`G`a` `r`a`v` ` ` ` \"))" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`1`+`1`=`5`t`I`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVl2(\"/`*`@` `}`;`)`8`j`Z`a`(`3`m`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}