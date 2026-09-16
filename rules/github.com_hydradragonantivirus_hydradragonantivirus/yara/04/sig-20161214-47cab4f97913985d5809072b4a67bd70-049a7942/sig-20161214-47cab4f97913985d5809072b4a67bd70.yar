rule sig_20161214_47cab4f97913985d5809072b4a67bd70 {
  meta:
    description = "datamaliciousorder - file 20161214_47cab4f97913985d5809072b4a67bd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5d2f1f0bd36f0bbf518104f60b02183a2b3b023f336e1069ce12716954769f4"

  strings:
    $s1  = "function aNJt2(aYb8) {eval(\"/*@cc_on var aBVi4 = new Date() @*/\");aBVi4[\"setUTCSeconds\"](\"0\", \"20\");if (aBVi4.getUTCMill" ascii
    $s2  = "function aNJt2(aYb8) {eval(\"/*@cc_on var aBVi4 = new Date() @*/\");aBVi4[\"setUTCSeconds\"](\"0\", \"20\");if (aBVi4.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`l`B`a`=`9`j`H" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"}`;`h`t`a`P`t`r`o`h`S`.`5`i`U`T`a` `n`r`u`t`e`r`;`)`9`j`H`a" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"}`;`h`t`a`P`t`r`o`h`S`.`5`i`U`T`a` `n`r`u`t`e`r`;`)`9`j`H`a" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"/`*`@` `}`;`6`k`R`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"/`*`@` `}`;`)`4`e`O`D`a`(`1`v`A`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"/`*`@` `}`;`1`g`T`N`a` `n`r`u`t`e`r`;`}`;`)`8`b`Q`K`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"/`*`@` `}`;`6`k`R`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` " ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\";`1`+`1`=`7`c`Z`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"/`*`@` `}`;`8`b`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJt2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}