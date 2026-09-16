rule sig_20161214_f9232f8248f68d223303b2d735413240 {
  meta:
    description = "datamaliciousorder - file 20161214_f9232f8248f68d223303b2d735413240.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58fd4fd2301d46cf49410a9c63fd4a1914e7a09aaf98a49093b882c1506e6cf4"

  strings:
    $s1  = "function aKMp9(aMk7) {eval(\"/*@cc_on var aYOm1 = new Date() @*/\");aYOm1[\"setUTCSeconds\"](\"0\", \"20\");if (aYOm1.getUTCMill" ascii
    $s2  = "function aKMp9(aMk7) {eval(\"/*@cc_on var aYOm1 = new Date() @*/\");aYOm1[\"setUTCSeconds\"](\"0\", \"20\");if (aYOm1.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\"/`*`@` `}`;`5`z`S`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii
    $s4  = "().toString(10) == \"20\") {var aOu1 = aMk7[\"split\"](\"`\"); return aOu1.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `3`p" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`1`q`M`Q`a` `+` `9`s`P`S`a`=`8`e`A`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `3" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\"/`*`@` `}`;`7`k`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `3" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`w`F`a`;`)`2` `,`5`w`P`T`a`(`]" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`e`A`a`=`8`p`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMp9(\"/`*`@` `}`;`1`u`O`a` `n`r`u`t`e`r`;`}`;`)`1`h`R`a`(`]`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}