rule sig_20161214_4230235bdabe9864df08e60d8f0b5ab3 {
  meta:
    description = "datamaliciousorder - file 20161214_4230235bdabe9864df08e60d8f0b5ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f5c8e474ac3f8506954829799406531558c51d8d73d6ee1d2b65c221d59f373"

  strings:
    $s1  = "function aSVx5(aFFi4) {eval(\"/*@cc_on var aFm7 = new Date() @*/\");aFm7[\"setUTCSeconds\"](\"0\", \"20\");if (aFm7.getUTCMillis" ascii
    $s2  = "function aSVx5(aFFi4) {eval(\"/*@cc_on var aFm7 = new Date() @*/\");aFm7[\"setUTCSeconds\"](\"0\", \"20\");if (aFm7.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"/`*`@` `}`;`7`z`N`a` `n`r`u`t`e`r`;`}`;`)`6`c`A`C`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"/`*`@` `}`;`)`8`r`V`a`(`4`y`A`L`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`f`X`a`;`)`2` `,`1`e`Y`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"/`*`@` `}`;`7`z`N`a` `n`r`u`t`e`r`;`}`;`)`6`c`A`C`a`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`f`B`a`=`4`e`U" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"/`*`@` `}`;`2`v`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`m" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`1`+`1`=`2`m`E`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`0` `=` `1`x`F`P`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"}`;`h`t`a`P`t`r`o`h`S`.`3`r`A`a` `n`r`u`t`e`r`;`)`4`e`U`O`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"/`*`@` `}`;`4`i`F`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSVx5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`f`X`a`;`)`2` `,`1`e`Y`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}