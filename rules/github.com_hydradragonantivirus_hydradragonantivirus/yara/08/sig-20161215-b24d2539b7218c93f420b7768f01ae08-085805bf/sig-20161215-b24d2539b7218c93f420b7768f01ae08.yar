rule sig_20161215_b24d2539b7218c93f420b7768f01ae08 {
  meta:
    description = "datamaliciousorder - file 20161215_b24d2539b7218c93f420b7768f01ae08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fbb7ff5f945599de7bbbbdb2a0da43a4fc7d147a403b0fe17f92ae9ef1f6649"

  strings:
    $s1  = "function aEo0(aZBq7) {eval(\"/*@cc_on var aSk8 = new Date() @*/\");aSk8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSk8[\"getUTC" ascii
    $s2  = "function aEo0(aZBq7) {eval(\"/*@cc_on var aSk8 = new Date() @*/\");aSk8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSk8[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\"/`*`@` `}`;`7`q`B`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s7  = "s\"]()[\"toString\"](10) == \"20\") {var aCf7 = aZBq7[\"split\"](\"`\"); return aCf7[\"reverse\"]().join(\"\");} else return \"" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`i`C`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\"/`*`@` `}`;`)`7`y`O`a`(`1`y`U`B`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`i`C`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\"/`*`@` `}`;`9`u`K`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\"/`*`@` `}`;`7`f`C`a` `n`r`u`t`e`r`;`}`;`)`3`e`D`D`a`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\"}`;`h`t`a`P`t`r`o`h`S`.`1`q`A`V`a` `n`r`u`t`e`r`;`)`8`q`P`V`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\"/`*`@` `}`;`9`u`K`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEo0(\";`1`e`T`a` `+` `8`l`K`a`=`3`c`K`F`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}