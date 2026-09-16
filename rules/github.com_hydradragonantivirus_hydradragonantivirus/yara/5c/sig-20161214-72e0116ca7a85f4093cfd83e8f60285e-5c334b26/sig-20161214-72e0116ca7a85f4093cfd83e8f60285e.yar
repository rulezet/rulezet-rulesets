rule sig_20161214_72e0116ca7a85f4093cfd83e8f60285e {
  meta:
    description = "datamaliciousorder - file 20161214_72e0116ca7a85f4093cfd83e8f60285e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08893c4179b284728df4be83367cd9e7dec27dde800b56fb4f490b099d856ceb"

  strings:
    $s1  = "function aRBw1(aGGp2) {eval(\"/*@cc_on var aBKh1 = new Date() @*/\");aBKh1[\"setUTCSeconds\"](\"0\", \"20\");if (aBKh1.getUTCMil" ascii
    $s2  = "function aRBw1(aGGp2) {eval(\"/*@cc_on var aBKh1 = new Date() @*/\");aBKh1[\"setUTCSeconds\"](\"0\", \"20\");if (aBKh1.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\"/`*`@` `}`;`7`n`K`Y`a` `n`r`u`t`e`r`;`}`;`)`8`y`Z`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\"}`;`h`t`a`P`t`r`o`h`S`.`5`s`K`F`a` `n`r`u`t`e`r`;`)`6`h`L`T" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`b`V`a`;`)`2` `,`4`h`M`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`1`+`1`=`5`o`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "s().toString(10) == \"20\") {var aYKn7 = aGGp2[\"split\"](\"`\"); return aYKn7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `1" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`b`V`a`;`)`2` `,`4`h`M`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\"/`*`@` `}`;`1`j`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`d" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`1`i`L`D`a` `+` `9`t`T`N`a`=`3`v`D`R`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`v`D`R`a`=`6`h" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRBw1(\"/`*`@` `}`;`)`8`p`I`K`a`(`7`p`F`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}