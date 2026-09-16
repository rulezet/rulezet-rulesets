rule sig_20161214_1999315e6a09cd87e2743b2ab146a9cc {
  meta:
    description = "datamaliciousorder - file 20161214_1999315e6a09cd87e2743b2ab146a9cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea8023112aeca9f54aa6e5820744855d896e5b6a8b0a90a11065256b9d14f3cd"

  strings:
    $s1  = "function aUy9(aVQi3) {eval(\"/*@cc_on var aBPx2 = new Date() @*/\");aBPx2[\"setUTCSeconds\"](\"0\", \"20\");if (aBPx2.getUTCMill" ascii
    $s2  = "function aUy9(aVQi3) {eval(\"/*@cc_on var aBPx2 = new Date() @*/\");aBPx2[\"setUTCSeconds\"](\"0\", \"20\");if (aBPx2.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `1`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\"/`*`@` `}`;`9`w`P`a` `n`r`u`t`e`r`;`}`;`)`7`n`D`G`a`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\"/`*`@` `}`;`)`4`n`X`a`(`5`x`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`7`m`E`a` `+` `3`g`X`a`=`8`a`G`D`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\"/`*`@` `}`;`4`a`W`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`a`G`D`a`=`7`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\"}`;`h`t`a`P`t`r`o`h`S`.`5`u`B`a` `n`r`u`t`e`r`;`)`7`v`R`a`(`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `1`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\"/`*`@` `}`;`)`4`n`X`a`(`5`x`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`a`G`D`a`=`7`v`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUy9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`x`S`a` `r`a`v` ` ` ` \")), 1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}