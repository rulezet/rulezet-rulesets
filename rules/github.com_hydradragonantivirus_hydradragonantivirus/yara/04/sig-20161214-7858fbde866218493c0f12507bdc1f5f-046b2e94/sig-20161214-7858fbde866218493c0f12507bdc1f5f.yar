rule sig_20161214_7858fbde866218493c0f12507bdc1f5f {
  meta:
    description = "datamaliciousorder - file 20161214_7858fbde866218493c0f12507bdc1f5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c59c05434e983ac1edb8a5baa0939aac6cb5e50a21620264ae442674c55ea783"

  strings:
    $s1  = "function aBSm1(aZKe7) {eval(\"/*@cc_on var aLVj5 = new Date() @*/\");aLVj5[\"setUTCSeconds\"](\"0\", \"20\");if (aLVj5.getUTCMil" ascii
    $s2  = "function aBSm1(aZKe7) {eval(\"/*@cc_on var aLVj5 = new Date() @*/\");aLVj5[\"setUTCSeconds\"](\"0\", \"20\");if (aLVj5.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`7`u`C`M`a` `+` `8`n`O`S`a`=`5`e`X`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`v`I`a`;`)`2` `,`8`e`T`L`a`(`]" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\"/`*`@` `}`;`)`5`p`P`a`(`2`i`D`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s10 = "s().toString(10) == \"20\") {var aKe3 = aZKe7[\"split\"](\"`\"); return aKe3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\"}`;`h`t`a`P`t`r`o`h`S`.`9`c`P`I`a` `n`r`u`t`e`r`;`)`6`u`O`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`v`I`a`;`)`2` `,`8`e`T`L`a`(`]" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\"/`*`@` `}`;`)`5`p`P`a`(`2`i`D`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\"}`;`h`t`a`P`t`r`o`h`S`.`9`c`P`I`a` `n`r`u`t`e`r`;`)`6`u`O`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`e`X`a`=`6`u`O" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\"/`*`@` `}`;`7`e`K`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\"/`*`@` `}`;`7`e`K`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBSm1(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}