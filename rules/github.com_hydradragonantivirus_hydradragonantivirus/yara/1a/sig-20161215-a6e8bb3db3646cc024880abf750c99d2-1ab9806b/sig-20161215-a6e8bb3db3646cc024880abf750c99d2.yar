rule sig_20161215_a6e8bb3db3646cc024880abf750c99d2 {
  meta:
    description = "datamaliciousorder - file 20161215_a6e8bb3db3646cc024880abf750c99d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "587df7ed555c1d87f775329e9ffb41dd47f3d5006a76c7fb14abcefc21e945dc"

  strings:
    $s1  = "function aSd8(aEz5) {eval(\"/*@cc_on var aZi7 = new Date() @*/\");aZi7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZi7[\"getUTCM" ascii
    $s2  = "function aSd8(aEz5) {eval(\"/*@cc_on var aZi7 = new Date() @*/\");aZi7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZi7[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` `" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\"/`*`@` `}`;`9`n`J`a` `n`r`u`t`e`r`;`}`;`)`6`m`M`Q`a`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\"/`*`@` `}`;`)`4`n`Q`a`(`1`v`T`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\"/`*`@` `}`;`6`j`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`m`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`x`G`a` `r`a`v` `;`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`j`A`D`a`=`1`l`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`8`k`U`a` `+` `1`i`I`a`=`5`j`A`D`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "\"]()[\"toString\"](10) == \"20\") {var aJn9 = aEz5[\"split\"](\"`\"); return aJn9[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSd8(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}