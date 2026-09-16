rule sig_20161214_78ce5be671b8ffcbe75bbd53f5dd1398 {
  meta:
    description = "datamaliciousorder - file 20161214_78ce5be671b8ffcbe75bbd53f5dd1398.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae297fcdad07ae1ea4d8ba4db8717addf1f95b6496f1b09bf584319c53f61e20"

  strings:
    $s1  = "function aQv3(aULw3) {eval(\"/*@cc_on var aAr0 = new Date() @*/\");aAr0[\"setUTCSeconds\"](\"0\", \"20\");if (aAr0.getUTCMillise" ascii
    $s2  = "function aQv3(aULw3) {eval(\"/*@cc_on var aAr0 = new Date() @*/\");aAr0[\"setUTCSeconds\"](\"0\", \"20\");if (aAr0.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\"/`*`@` `}`;`2`v`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`w`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\"/`*`@` `}`;`)`4`k`D`A`a`(`3`j`D`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`n`N`a`(`h`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\"/`*`@` `}`;`)`4`k`D`A`a`(`3`j`D`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`1`+`1`=`1`e`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`1`+`1`=`1`e`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\"}`;`h`t`a`P`t`r`o`h`S`.`5`u`K`a` `n`r`u`t`e`r`;`)`8`z`X`a`(`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\"/`*`@` `}`;`3`x`G`a` `n`r`u`t`e`r`;`}`;`)`5`w`B`C`a`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`o`O`a`=`8`z`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`a`M`T`a`;`)`2` `,`0`x`Q`E`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQv3(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`n`N`a`(`h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}