rule sig_20161215_7650b1910bb2b15f3bc5bf197c7e32dc {
  meta:
    description = "datamaliciousorder - file 20161215_7650b1910bb2b15f3bc5bf197c7e32dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecee8a7e3685c6e42a41914b812f9cb3dd40809ce7b166edeb4f7dfa96c6d197"

  strings:
    $s1  = "function aMDb0(aIb4) {eval(\"/*@cc_on var aFIx8 = new Date() @*/\");aFIx8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFIx8[\"get" ascii
    $s2  = "function aMDb0(aIb4) {eval(\"/*@cc_on var aFIx8 = new Date() @*/\");aFIx8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFIx8[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`d`I`U`a`=`0`r" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`t`S`J`a` `r`a`v` `;" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`4`x`G`R`a` `+` `0`s`X`a`=`9`d`I`U`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\"}`;`h`t`a`P`t`r`o`h`S`.`2`r`S`N`a` `n`r`u`t`e`r`;`)`0`r`M`N" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\"}`;`h`t`a`P`t`r`o`h`S`.`2`r`S`N`a` `n`r`u`t`e`r`;`)`0`r`M`N" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\"/`*`@` `}`;`)`7`f`I`D`a`(`9`b`G`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMDb0(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `4" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}