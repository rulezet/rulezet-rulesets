rule sig_20161215_d8d79e7d232ecd67b2661891ee63cf54 {
  meta:
    description = "datamaliciousorder - file 20161215_d8d79e7d232ecd67b2661891ee63cf54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ee2a2de12cc65a9b88c884b451d09e0ac4a2bd51e82159f5903e115697efd96"

  strings:
    $s1  = "function aFx1(aPXv7) {eval(\"/*@cc_on var aUx7 = new Date() @*/\");aUx7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUx7[\"getUTC" ascii
    $s2  = "function aFx1(aPXv7) {eval(\"/*@cc_on var aUx7 = new Date() @*/\");aUx7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUx7[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`k`T`a` `r`a`v` `;`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`r`I`a`=`8`z`A`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\"/`*`@` `}`;`)`9`u`C`a`(`8`n`K`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`k`T`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "s\"]()[\"toString\"](10) == \"20\") {var aZBy9 = aPXv7[\"split\"](\"`\"); return aZBy9[\"reverse\"]().join(\"\");} else return " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`r`I`a`=`8`z`A`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\"/`*`@` `}`;`7`v`X`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\"}`;`h`t`a`P`t`r`o`h`S`.`7`p`M`R`a` `n`r`u`t`e`r`;`)`8`z`A`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`g`P`H`a` `r`a`v` ` ` ` \"))," ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\"/`*`@` `}`;`6`g`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`0` `=` `9`o`V`D`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFx1(\";`1`+`1`=`8`m`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}