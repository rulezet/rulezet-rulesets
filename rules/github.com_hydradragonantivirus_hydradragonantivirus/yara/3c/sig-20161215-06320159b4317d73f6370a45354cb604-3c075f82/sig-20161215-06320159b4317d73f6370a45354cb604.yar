rule sig_20161215_06320159b4317d73f6370a45354cb604 {
  meta:
    description = "datamaliciousorder - file 20161215_06320159b4317d73f6370a45354cb604.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c77803b2a3776d6144387c2510d8701b1758ea2e4ed747d0f03205b3230704d"

  strings:
    $s1  = "function aSBt5(aRq7) {eval(\"/*@cc_on var aKWe6 = new Date() @*/\");aKWe6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKWe6[\"get" ascii
    $s2  = "function aSBt5(aRq7) {eval(\"/*@cc_on var aKWe6 = new Date() @*/\");aKWe6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKWe6[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\"/`*`@` `}`;`3`x`V`U`a` `n`r`u`t`e`r`;`}`;`)`1`e`G`H`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "onds\"]()[\"toString\"](10) == \"20\") {var aUVx3 = aRq7[\"split\"](\"`\"); return aUVx3[\"reverse\"]().join(\"\");} else return" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`a`D`a`=`8`x`T" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`1`+`1`=`1`e`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`j`R`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\"/`*`@` `}`;`7`q`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`p`Y`a`;`)`2` `,`9`k`D`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSBt5(\"}`;`h`t`a`P`t`r`o`h`S`.`6`s`D`F`a` `n`r`u`t`e`r`;`)`8`x`T`R" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}