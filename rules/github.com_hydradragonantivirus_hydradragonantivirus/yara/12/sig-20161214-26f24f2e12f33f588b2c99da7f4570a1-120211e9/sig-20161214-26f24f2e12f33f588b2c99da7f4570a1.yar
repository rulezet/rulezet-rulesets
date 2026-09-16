rule sig_20161214_26f24f2e12f33f588b2c99da7f4570a1 {
  meta:
    description = "datamaliciousorder - file 20161214_26f24f2e12f33f588b2c99da7f4570a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7b2e1ac0238a9b26ebf6b6d231313ce8519afc6f278fac4ad5c5ae6838b153b"

  strings:
    $s1  = "function aOKy6(aEm1) {eval(\"/*@cc_on var aNk5 = new Date() @*/\");aNk5[\"setUTCSeconds\"](\"0\", \"20\");if (aNk5.getUTCMillise" ascii
    $s2  = "function aOKy6(aEm1) {eval(\"/*@cc_on var aNk5 = new Date() @*/\");aNk5[\"setUTCSeconds\"](\"0\", \"20\");if (aNk5.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`x`F`A`a` `r`a`v` ` ` ` \"))" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`j`C`X`a`;`)`2` `,`6`x`C`Q`a`(" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\"/`*`@` `}`;`)`3`t`A`a`(`6`t`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\"}`;`h`t`a`P`t`r`o`h`S`.`3`q`R`a` `n`r`u`t`e`r`;`)`4`d`Q`G`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\"}`;`h`t`a`P`t`r`o`h`S`.`3`q`R`a` `n`r`u`t`e`r`;`)`4`d`Q`G`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`0` `=` `7`r`S`Y`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`m`R`G`a`=`4`d" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\"/`*`@` `}`;`1`m`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOKy6(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}