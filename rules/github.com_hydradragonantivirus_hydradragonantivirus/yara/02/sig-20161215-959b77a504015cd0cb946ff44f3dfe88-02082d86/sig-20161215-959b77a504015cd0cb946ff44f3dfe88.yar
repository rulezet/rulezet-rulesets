rule sig_20161215_959b77a504015cd0cb946ff44f3dfe88 {
  meta:
    description = "datamaliciousorder - file 20161215_959b77a504015cd0cb946ff44f3dfe88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9ac51b5a9fa6ed51a39f11d9dffcee5bb8ce940857144506ee411473f35d4ef"

  strings:
    $s1  = "function aHVu3(aOl7) {eval(\"/*@cc_on var aAy9 = new Date() @*/\");aAy9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAy9[\"getUTC" ascii
    $s2  = "function aHVu3(aOl7) {eval(\"/*@cc_on var aAy9 = new Date() @*/\");aAy9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAy9[\"getUTC" ascii
    $s3  = "s\"]()[\"toString\"](10) == \"20\") {var aPf9 = aOl7[\"split\"](\"`\"); return aPf9[\"reverse\"]().join(\"\");} else return \"\"" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `3`y`Z" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\"}`;`h`t`a`P`t`r`o`h`S`.`3`t`V`V`a` `n`r`u`t`e`r`;`)`8`e`B`K" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\"/`*`@` `}`;`7`l`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`1`+`1`=`8`d`I`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`0` `=` `2`r`U`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`a`R`J`a` `r`a`v` ` ` ` \"))" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\"}`;`h`t`a`P`t`r`o`h`S`.`3`t`V`V`a` `n`r`u`t`e`r`;`)`8`e`B`K" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHVu3(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `3`y`Z" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}