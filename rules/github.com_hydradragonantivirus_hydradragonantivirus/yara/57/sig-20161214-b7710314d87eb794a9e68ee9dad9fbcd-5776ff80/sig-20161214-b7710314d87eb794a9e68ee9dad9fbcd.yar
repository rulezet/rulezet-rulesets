rule sig_20161214_b7710314d87eb794a9e68ee9dad9fbcd {
  meta:
    description = "datamaliciousorder - file 20161214_b7710314d87eb794a9e68ee9dad9fbcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03edfbb00cf4eeb58b030e11a7ecbdd6873b3cbf83c739468c9d8751998ba8e8"

  strings:
    $s1  = "function aNUs8(aSAx1) {eval(\"/*@cc_on var aABa9 = new Date() @*/\");aABa9[\"setUTCSeconds\"](\"0\", \"20\");if (aABa9.getUTCMil" ascii
    $s2  = "function aNUs8(aSAx1) {eval(\"/*@cc_on var aABa9 = new Date() @*/\");aABa9[\"setUTCSeconds\"](\"0\", \"20\");if (aABa9.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`n`Q`a`;`)`2` `,`1`r`C`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\"/`*`@` `}`;`3`x`E`H`a` `n`r`u`t`e`r`;`}`;`)`9`f`J`a`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`b`U`Z`a` `r`a`v` ` ` ` \"))" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `2`w`T`Y`a`(" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`1`+`1`=`0`b`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\"/`*`@` `}`;`1`x`A`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\"}`;`h`t`a`P`t`r`o`h`S`.`8`s`P`a` `n`r`u`t`e`r`;`)`0`y`G`a`(" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\"/`*`@` `}`;`6`x`S`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`0` `=` `8`p`R`L`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\"/`*`@` `}`;`)`6`m`G`a`(`7`v`F`F`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNUs8(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x" ascii
    $s20 = "s().toString(10) == \"20\") {var aHEx3 = aSAx1[\"split\"](\"`\"); return aHEx3.reverse().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}