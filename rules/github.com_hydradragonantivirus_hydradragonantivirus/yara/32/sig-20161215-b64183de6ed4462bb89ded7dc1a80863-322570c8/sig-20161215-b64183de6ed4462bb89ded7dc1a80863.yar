rule sig_20161215_b64183de6ed4462bb89ded7dc1a80863 {
  meta:
    description = "datamaliciousorder - file 20161215_b64183de6ed4462bb89ded7dc1a80863.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79ac562319fb736792d9b6e0738c27c62c7cf50d3fca89db9d44c43f1b67c1ad"

  strings:
    $s1  = "function aTm7(aHq2) {eval(\"/*@cc_on var aPb1 = new Date() @*/\");aPb1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPb1[\"getUTCM" ascii
    $s2  = "function aTm7(aHq2) {eval(\"/*@cc_on var aPb1 = new Date() @*/\");aPb1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPb1[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`z`F`a`=`2`x`D`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\"\")), 1);" fullword ascii
    $s6  = "\"]()[\"toString\"](10) == \"20\") {var aOv3 = aHq2[\"split\"](\"`\"); return aOv3[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`1`+`1`=`4`y`O`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`4`o`A`B`a` `+` `3`f`J`a`=`9`z`F`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`d`L`E`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\"/`*`@` `}`;`3`v`O`a` `n`r`u`t`e`r`;`}`;`)`5`s`Z`a`(`]`\\x22`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`z`F`a`=`2`x`D`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`v`M`a`;`)`2` `,`0`c`J`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTm7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`l`X`a` `r`a`v` ` ` ` \")), 1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}