rule sig_20161214_428e1000179a4c24e1a791a9368823ef {
  meta:
    description = "datamaliciousorder - file 20161214_428e1000179a4c24e1a791a9368823ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a1b0376fb3b28a26b56153c94200cfad066e6ee7f313dfb2848bf9ce997aba6"

  strings:
    $s1  = "function aPt6(aHGp9) {eval(\"/*@cc_on var aZGo5 = new Date() @*/\");aZGo5[\"setUTCSeconds\"](\"0\", \"20\");if (aZGo5.getUTCMill" ascii
    $s2  = "function aPt6(aHGp9) {eval(\"/*@cc_on var aZGo5 = new Date() @*/\");aZGo5[\"setUTCSeconds\"](\"0\", \"20\");if (aZGo5.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`j`G`a`;`)`2` `,`6`o`B`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\"/`*`@` `}`;`9`p`G`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`3`z`X`E`a` `+` `8`z`H`S`a`=`2`k`D`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\"}`;`h`t`a`P`t`r`o`h`S`.`2`c`J`a` `n`r`u`t`e`r`;`)`8`l`B`S`a`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\"/`*`@` `}`;`5`o`W`D`a` `n`r`u`t`e`r`;`}`;`)`9`i`H`B`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`k`D`a`=`8`l`B`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`0` `=` `4`h`H`Y`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\"/`*`@` `}`;`)`1`u`W`a`(`1`p`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt6(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}