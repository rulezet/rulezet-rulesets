rule sig_20161214_8a346fe46e29dea34f274a76e2864a70 {
  meta:
    description = "datamaliciousorder - file 20161214_8a346fe46e29dea34f274a76e2864a70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31cdc0f4b2456df908bf45bc52d616f14c0387403d4d62b052459cf2d5a7b33b"

  strings:
    $s1  = "function aUXv5(aCLq3) {eval(\"/*@cc_on var aHNp7 = new Date() @*/\");aHNp7[\"setUTCSeconds\"](\"0\", \"20\");if (aHNp7.getUTCMil" ascii
    $s2  = "function aUXv5(aCLq3) {eval(\"/*@cc_on var aHNp7 = new Date() @*/\");aHNp7[\"setUTCSeconds\"](\"0\", \"20\");if (aHNp7.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`n`S`a` `r`a`v` ` ` ` \")), " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`p`T`a`=`3`o`R" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\"}`;`h`t`a`P`t`r`o`h`S`.`7`q`E`N`a` `n`r`u`t`e`r`;`)`3`o`R`a" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\"/`*`@` `}`;`)`6`o`W`a`(`2`u`R`S`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`m`S`a`;`)`2` `,`6`x`A`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\"/`*`@` `}`;`3`q`L`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`p`T`a`=`3`o`R" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\"/`*`@` `}`;`3`w`Q`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\"/`*`@` `}`;`6`n`I`Z`a` `n`r`u`t`e`r`;`}`;`)`3`z`T`a`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUXv5(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}