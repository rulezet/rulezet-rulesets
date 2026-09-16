rule sig_20161214_c13b918ef5157006df2f0e654becd8e6 {
  meta:
    description = "datamaliciousorder - file 20161214_c13b918ef5157006df2f0e654becd8e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b2ce96ab7263b1fca40476451f8d03f9e1f5b1fb912a951da4631f616f62212"

  strings:
    $s1  = "function aWl3(aJr6) {eval(\"/*@cc_on var aMo0 = new Date() @*/\");aMo0[\"setUTCSeconds\"](\"0\", \"20\");if (aMo0.getUTCMillisec" ascii
    $s2  = "function aWl3(aJr6) {eval(\"/*@cc_on var aMo0 = new Date() @*/\");aMo0[\"setUTCSeconds\"](\"0\", \"20\");if (aMo0.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\"}`;`h`t`a`P`t`r`o`h`S`.`4`t`K`V`a` `n`r`u`t`e`r`;`)`3`m`F`M`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`e`M`a`=`3`m`F`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\"/`*`@` `}`;`6`r`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\"/`*`@` `}`;`)`4`f`C`O`a`(`8`p`F`L`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`1`+`1`=`4`x`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`8`a`H`a` `+` `0`y`U`a`=`8`e`M`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\"/`*`@` `}`;`)`4`f`C`O`a`(`8`p`F`L`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\"/`*`@` `}`;`0`u`X`U`a` `n`r`u`t`e`r`;`}`;`)`7`d`Y`a`(`]`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `5`o`A`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "oString(10) == \"20\") {var aUXu0 = aJr6[\"split\"](\"`\"); return aUXu0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`e`M`a`=`3`m`F`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl3(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `5`o`A`a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}