rule sig_20161214_01125108b95b12dbc448789105840674 {
  meta:
    description = "datamaliciousorder - file 20161214_01125108b95b12dbc448789105840674.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e0f39eb0e12ccd29fee990cb596813f03fa8b470226027d1a17bf7ac3e86789"

  strings:
    $s1  = "function aLx4(aCx2) {eval(\"/*@cc_on var aYx9 = new Date() @*/\");aYx9[\"setUTCSeconds\"](\"0\", \"20\");if (aYx9.getUTCMillisec" ascii
    $s2  = "function aLx4(aCx2) {eval(\"/*@cc_on var aYx9 = new Date() @*/\");aYx9[\"setUTCSeconds\"](\"0\", \"20\");if (aYx9.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`1`+`1`=`5`b`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `8`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`a`B`Y`a`;`)`2` `,`1`s`T`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`0`y`H`a` `+` `2`y`G`J`a`=`0`j`M`H`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`j`M`H`a`=`8`b`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\"}`;`h`t`a`P`t`r`o`h`S`.`5`y`N`R`a` `n`r`u`t`e`r`;`)`8`b`R`W`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\"/`*`@` `}`;`2`x`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`m`E`a` `r`a`v` ` ` ` \")), 1" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLx4(\"/`*`@` `}`;`3`c`Z`G`a` `n`r`u`t`e`r`;`}`;`)`2`q`K`a`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}