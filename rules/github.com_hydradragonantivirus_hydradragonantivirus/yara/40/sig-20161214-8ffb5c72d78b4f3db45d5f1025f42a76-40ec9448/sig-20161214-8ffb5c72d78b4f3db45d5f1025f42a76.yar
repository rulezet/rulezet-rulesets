rule sig_20161214_8ffb5c72d78b4f3db45d5f1025f42a76 {
  meta:
    description = "datamaliciousorder - file 20161214_8ffb5c72d78b4f3db45d5f1025f42a76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d7739a6ed89b2001e71179738b0698c9147e2a4ca3f430c0f93df5f6be5c843"

  strings:
    $s1  = "function aXs6(aTOw8) {eval(\"/*@cc_on var aSEb3 = new Date() @*/\");aSEb3[\"setUTCSeconds\"](\"0\", \"20\");if (aSEb3.getUTCMill" ascii
    $s2  = "function aXs6(aTOw8) {eval(\"/*@cc_on var aSEb3 = new Date() @*/\");aSEb3[\"setUTCSeconds\"](\"0\", \"20\");if (aSEb3.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\"/`*`@` `}`;`2`e`Y`U`a` `n`r`u`t`e`r`;`}`;`)`4`t`Q`L`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\"/`*`@` `}`;`1`j`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`l`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`q`Q`F`a`;`)`2` `,`8`o`N`T`a`(`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`1`k`F`K`a` `+` `3`i`M`J`a`=`4`i`O`U`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\"/`*`@` `}`;`2`e`Y`U`a` `n`r`u`t`e`r`;`}`;`)`4`t`Q`L`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`d`V`M`a` `n`r`u`t`e`r`;`)`0`i`S`S`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\"/`*`@` `}`;`8`w`O`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\"/`*`@` `}`;`)`2`h`M`a`(`4`t`Q`J`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXs6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}