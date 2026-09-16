rule sig_20161214_1b8c4c4d893243db9819bfb2e1a69fda {
  meta:
    description = "datamaliciousorder - file 20161214_1b8c4c4d893243db9819bfb2e1a69fda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88b223e015de8ceb9a977595127571936e51e567324de2f47f9a61dda143154a"

  strings:
    $s1  = "function aAXy9(aVDr7) {eval(\"/*@cc_on var aNb8 = new Date() @*/\");aNb8[\"setUTCSeconds\"](\"0\", \"20\");if (aNb8.getUTCMillis" ascii
    $s2  = "function aAXy9(aVDr7) {eval(\"/*@cc_on var aNb8 = new Date() @*/\");aNb8[\"setUTCSeconds\"](\"0\", \"20\");if (aNb8.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`1`+`1`=`8`j`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`2`x`Y`a` `+` `9`s`T`a`=`5`f`E`S`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `2`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`f`E`S`a`=`8`f" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\"/`*`@` `}`;`)`8`x`B`a`(`2`c`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\"/`*`@` `}`;`4`m`T`Y`a` `n`r`u`t`e`r`;`}`;`)`4`a`S`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`1`+`1`=`8`j`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`0` `=` `3`u`Z`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\"}`;`h`t`a`P`t`r`o`h`S`.`9`w`O`a` `n`r`u`t`e`r`;`)`8`f`O`a`(" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`f`E`S`a`=`8`f" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAXy9(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}