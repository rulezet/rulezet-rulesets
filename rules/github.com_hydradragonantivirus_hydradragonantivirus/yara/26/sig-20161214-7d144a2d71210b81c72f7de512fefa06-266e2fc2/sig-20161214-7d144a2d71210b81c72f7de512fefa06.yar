rule sig_20161214_7d144a2d71210b81c72f7de512fefa06 {
  meta:
    description = "datamaliciousorder - file 20161214_7d144a2d71210b81c72f7de512fefa06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3ab0e0f440bc7c41f416b3123b5c6a94d1d70d72fb298722ae5cf5468a1d9e"

  strings:
    $s1  = "function aEMi0(aRm7) {eval(\"/*@cc_on var aHz1 = new Date() @*/\");aHz1[\"setUTCSeconds\"](\"0\", \"20\");if (aHz1.getUTCMillise" ascii
    $s2  = "function aEMi0(aRm7) {eval(\"/*@cc_on var aHz1 = new Date() @*/\");aHz1[\"setUTCSeconds\"](\"0\", \"20\");if (aHz1.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\"}`;`h`t`a`P`t`r`o`h`S`.`5`t`C`B`a` `n`r`u`t`e`r`;`)`6`u`L`a" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`n`R`a`=`6`u`L" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\"}`;`h`t`a`P`t`r`o`h`S`.`5`t`C`B`a` `n`r`u`t`e`r`;`)`6`u`L`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`c`Z`a`;`)`2` `,`1`m`D`X`a`(`]" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`9`e`Z`a` `+` `9`z`K`F`a`=`8`n`R`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\"/`*`@` `}`;`)`9`p`X`a`(`5`u`K`N`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\"/`*`@` `}`;`3`d`G`N`a` `n`r`u`t`e`r`;`}`;`)`6`x`O`A`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEMi0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}