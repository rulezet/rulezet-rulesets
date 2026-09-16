rule sig_20161214_abd46ab08e7bb1fade5b252e0b7dc26b {
  meta:
    description = "datamaliciousorder - file 20161214_abd46ab08e7bb1fade5b252e0b7dc26b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21a46f1a3a2b59020f128bbc9cf07976d6a1bb0133909b4258b40ddafd9f1d5e"

  strings:
    $s1  = "function aFs0(aPd1) {eval(\"/*@cc_on var aBMp3 = new Date() @*/\");aBMp3[\"setUTCSeconds\"](\"0\", \"20\");if (aBMp3.getUTCMilli" ascii
    $s2  = "function aFs0(aPd1) {eval(\"/*@cc_on var aBMp3 = new Date() @*/\");aBMp3[\"setUTCSeconds\"](\"0\", \"20\");if (aBMp3.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`2`o`C`a` `+` `8`y`R`a`=`7`j`J`C`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`0` `=` `4`d`D`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`1`+`1`=`4`a`I`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`1`+`1`=`4`a`I`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\"/`*`@` `}`;`)`9`c`D`K`a`(`9`e`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\"/`*`@` `}`;`9`f`P`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\"/`*`@` `}`;`3`t`Q`Z`a` `n`r`u`t`e`r`;`}`;`)`8`k`R`a`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\"/`*`@` `}`;`)`9`c`D`K`a`(`9`e`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s19 = ").toString(10) == \"20\") {var aZQt3 = aPd1[\"split\"](\"`\"); return aZQt3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFs0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}