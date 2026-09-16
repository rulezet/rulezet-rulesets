rule sig_20161214_c9f57ce95b2b7a32b5630a824c4b8b58 {
  meta:
    description = "datamaliciousorder - file 20161214_c9f57ce95b2b7a32b5630a824c4b8b58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38f1a5b9b0481bf167f2c0ae55aa72ade053ad9691dd0b739224c56fcaedf139"

  strings:
    $s1  = "function aMp4(aAKu5) {eval(\"/*@cc_on var aEBz7 = new Date() @*/\");aEBz7[\"setUTCSeconds\"](\"0\", \"20\");if (aEBz7.getUTCMill" ascii
    $s2  = "function aMp4(aAKu5) {eval(\"/*@cc_on var aEBz7 = new Date() @*/\");aEBz7[\"setUTCSeconds\"](\"0\", \"20\");if (aEBz7.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`k`R`a`=`4`x`M`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\"}`;`h`t`a`P`t`r`o`h`S`.`4`g`A`X`a` `n`r`u`t`e`r`;`)`4`x`M`F`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`k`R`a`=`4`x`M`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`.`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`t`Y`O`a`;`)`2` `,`0`l`L`N`a`(`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\"/`*`@` `}`;`6`c`E`Y`a` `n`r`u`t`e`r`;`}`;`)`2`i`B`a`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\"/`*`@` `}`;`6`c`E`Y`a` `n`r`u`t`e`r`;`}`;`)`2`i`B`a`(`]`\\x2" ascii
    $s19 = "().toString(10) == \"20\") {var aYEc6 = aAKu5[\"split\"](\"`\"); return aYEc6.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMp4(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}