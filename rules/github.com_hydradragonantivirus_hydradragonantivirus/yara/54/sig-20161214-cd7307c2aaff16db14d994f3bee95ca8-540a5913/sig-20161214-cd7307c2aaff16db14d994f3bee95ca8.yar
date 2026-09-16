rule sig_20161214_cd7307c2aaff16db14d994f3bee95ca8 {
  meta:
    description = "datamaliciousorder - file 20161214_cd7307c2aaff16db14d994f3bee95ca8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2528c608aabfbe374b7e05b948bbd3730405e86e3c72aeaa39b5d66d724dc2b7"

  strings:
    $s1  = "function aRq3(aXNi8) {eval(\"/*@cc_on var aEYe0 = new Date() @*/\");aEYe0[\"setUTCSeconds\"](\"0\", \"20\");if (aEYe0.getUTCMill" ascii
    $s2  = "function aRq3(aXNi8) {eval(\"/*@cc_on var aEYe0 = new Date() @*/\");aEYe0[\"setUTCSeconds\"](\"0\", \"20\");if (aEYe0.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`1`+`1`=`5`g`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\"/`*`@` `}`;`8`i`N`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`f`Z`V`a` `r`a`v` ` ` ` \"))," ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `7`x`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\"/`*`@` `}`;`)`9`l`E`I`a`(`5`l`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s13 = "().toString(10) == \"20\") {var aLKd8 = aXNi8[\"split\"](\"`\"); return aLKd8.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\"/`*`@` `}`;`5`f`X`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\"/`*`@` `}`;`8`d`K`L`a` `n`r`u`t`e`r`;`}`;`)`8`l`X`T`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `7`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`v`Q`a`=`6`i`R`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRq3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}