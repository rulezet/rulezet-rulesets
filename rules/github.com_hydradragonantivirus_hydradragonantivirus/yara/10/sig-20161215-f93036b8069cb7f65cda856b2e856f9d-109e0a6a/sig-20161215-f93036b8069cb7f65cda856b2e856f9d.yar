rule sig_20161215_f93036b8069cb7f65cda856b2e856f9d {
  meta:
    description = "datamaliciousorder - file 20161215_f93036b8069cb7f65cda856b2e856f9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bdca4aa0eff56e28d1f8eff43306bbb764cff62413bf7e0f14adb71cdcb81ad"

  strings:
    $s1  = "function aYNh0(aVUv4) {eval(\"/*@cc_on var aLd4 = new Date() @*/\");aLd4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLd4[\"getUT" ascii
    $s2  = "function aYNh0(aVUv4) {eval(\"/*@cc_on var aLd4 = new Date() @*/\");aLd4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLd4[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `6" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`u`Z`P`a` `n`r`u`t`e`r`;`)`2`o`Y`L" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`u`Z`P`a` `n`r`u`t`e`r`;`)`2`o`Y`L" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`0` `=` `9`c`U`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\"/`*`@` `}`;`6`f`H`a` `n`r`u`t`e`r`;`}`;`)`3`z`J`A`a`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\"/`*`@` `}`;`4`v`U`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYNh0(\";`1`+`1`=`4`j`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}