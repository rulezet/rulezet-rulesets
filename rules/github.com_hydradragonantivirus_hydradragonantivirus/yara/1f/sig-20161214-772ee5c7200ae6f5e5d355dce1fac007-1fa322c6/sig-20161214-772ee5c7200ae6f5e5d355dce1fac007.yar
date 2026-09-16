rule sig_20161214_772ee5c7200ae6f5e5d355dce1fac007 {
  meta:
    description = "datamaliciousorder - file 20161214_772ee5c7200ae6f5e5d355dce1fac007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33ff9073a8fac3760a1212a55dcbdffb54c02e95376245247241580a7f9fa5d7"

  strings:
    $s1  = "function aNBb3(aIv7) {eval(\"/*@cc_on var aRUb1 = new Date() @*/\");aRUb1[\"setUTCSeconds\"](\"0\", \"20\");if (aRUb1.getUTCMill" ascii
    $s2  = "function aNBb3(aIv7) {eval(\"/*@cc_on var aRUb1 = new Date() @*/\");aRUb1[\"setUTCSeconds\"](\"0\", \"20\");if (aRUb1.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`v`M`a`=`0`m`T" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`v`M`a`=`0`m`T" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`f`R`a` `n`r`u`t`e`r`;`)`0`m`T`A`a" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`f`R`a` `n`r`u`t`e`r`;`)`0`m`T`A`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`r`R`N`a`;`)`2` `,`2`d`E`a`(`]" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`1`+`1`=`5`y`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`x`H`a` `r`a`v` ` ` ` \")), " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBb3(\"/`*`@` `}`;`6`v`K`B`a` `n`r`u`t`e`r`;`}`;`)`6`x`F`a`(`]`\\x" ascii
    $s20 = "().toString(10) == \"20\") {var aBKv6 = aIv7[\"split\"](\"`\"); return aBKv6.reverse().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}