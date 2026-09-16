rule sig_20161215_a595ce7e65ab81c830315005153c5d14 {
  meta:
    description = "datamaliciousorder - file 20161215_a595ce7e65ab81c830315005153c5d14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf8496c2d7de54b19a5e0374ea0fb8e24235129321fe100ec983faca5724c3ca"

  strings:
    $s1  = "function aPOt0(aRq1) {eval(\"/*@cc_on var aQi6 = new Date() @*/\");aQi6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQi6[\"getUTC" ascii
    $s2  = "function aPOt0(aRq1) {eval(\"/*@cc_on var aQi6 = new Date() @*/\");aQi6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQi6[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`m`D`T`a` `r`a`v` ` ` ` \"))" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`0` `=` `6`d`J`A`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "s\"]()[\"toString\"](10) == \"20\") {var aPb8 = aRq1[\"split\"](\"`\"); return aPb8[\"reverse\"]().join(\"\");} else return \"\"" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\"}`;`h`t`a`P`t`r`o`h`S`.`7`n`F`H`a` `n`r`u`t`e`r`;`)`8`a`Q`C" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `9`m`R" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`o`A`M`a`=`8`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`o`A`M`a`=`8`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\"/`*`@` `}`;`7`z`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`r" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`1`+`1`=`6`x`M`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\"/`*`@` `}`;`7`z`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`r" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPOt0(\"\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}