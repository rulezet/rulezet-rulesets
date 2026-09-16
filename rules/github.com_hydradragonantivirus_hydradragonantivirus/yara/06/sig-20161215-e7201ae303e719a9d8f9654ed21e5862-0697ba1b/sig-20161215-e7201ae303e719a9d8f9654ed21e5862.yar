rule sig_20161215_e7201ae303e719a9d8f9654ed21e5862 {
  meta:
    description = "datamaliciousorder - file 20161215_e7201ae303e719a9d8f9654ed21e5862.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0400f284886600ba8175c373496b405fce40883e71a5dd6e1b7315473c2a6f67"

  strings:
    $s1  = "function aIl6(aEp2) {eval(\"/*@cc_on var aRBw5 = new Date() @*/\");aRBw5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRBw5[\"getU" ascii
    $s2  = "function aIl6(aEp2) {eval(\"/*@cc_on var aRBw5 = new Date() @*/\");aRBw5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRBw5[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\"/`*`@` `}`;`3`w`R`a` `n`r`u`t`e`r`;`}`;`)`5`k`Q`a`(`]`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\"/`*`@` `}`;`)`5`d`O`T`a`(`4`b`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` `" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\"}`;`h`t`a`P`t`r`o`h`S`.`8`a`X`a` `n`r`u`t`e`r`;`)`0`i`Z`S`a`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`x`O`P`a`=`0`i`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `8`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`x`Y`a` `r`a`v` `;`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`e`H`P`a`;`)`2` `,`7`a`U`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\"/`*`@` `}`;`3`w`R`a` `n`r`u`t`e`r`;`}`;`)`5`k`Q`a`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`x`Y`a` `r`a`v` `;`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\"/`*`@` `}`;`5`v`N`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIl6(\"/`*`@` `}`;`2`p`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}