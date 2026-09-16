rule sig_20161214_56814e97937d277e2cff18372e766c3c {
  meta:
    description = "datamaliciousorder - file 20161214_56814e97937d277e2cff18372e766c3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "659f535fe6bb3e0001860ad8d8bbf7fbf21b7d2d6433fd68a8b94249898d94b0"

  strings:
    $s1  = "function aAq8(aFj3) {eval(\"/*@cc_on var aCXv0 = new Date() @*/\");aCXv0[\"setUTCSeconds\"](\"0\", \"20\");if (aCXv0.getUTCMilli" ascii
    $s2  = "function aAq8(aFj3) {eval(\"/*@cc_on var aCXv0 = new Date() @*/\");aCXv0[\"setUTCSeconds\"](\"0\", \"20\");if (aCXv0.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`.`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`.`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`i`T`a` `r`a`v` ` ` ` \")), 1" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\"/`*`@` `}`;`3`x`S`F`a` `n`r`u`t`e`r`;`}`;`)`7`z`C`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\"/`*`@` `}`;`)`4`s`J`E`a`(`2`m`V`Q`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\"}`;`h`t`a`P`t`r`o`h`S`.`3`t`M`a` `n`r`u`t`e`r`;`)`6`t`O`C`a`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\"/`*`@` `}`;`3`j`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` `" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`1`+`1`=`1`n`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`c`V`I`a`=`6`t`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\"}`;`h`t`a`P`t`r`o`h`S`.`3`t`M`a` `n`r`u`t`e`r`;`)`6`t`O`C`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAq8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}