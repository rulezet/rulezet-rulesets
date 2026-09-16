rule sig_20161215_f3b877ced036ceaf70d6bb45373c005c {
  meta:
    description = "datamaliciousorder - file 20161215_f3b877ced036ceaf70d6bb45373c005c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd21cdd4a3596394ebabf3297a9a8ce9162f1756aa3323f4a8871f7c5416a6df"

  strings:
    $s1  = "function aDVy0(aHs2) {eval(\"/*@cc_on var aXv0 = new Date() @*/\");aXv0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXv0[\"getUTC" ascii
    $s2  = "function aDVy0(aHs2) {eval(\"/*@cc_on var aXv0 = new Date() @*/\");aXv0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXv0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`q`Z`N`a`=`3`w" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\"/`*`@` `}`;`2`s`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`x`P`a`;`)`2` `,`8`w`Z`G`a`(`]" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`2`h`W`N`a` `+` `4`y`I`D`a`=`3`q`Z`N`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`0` `=` `5`y`C`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "s\"]()[\"toString\"](10) == \"20\") {var aJAd5 = aHs2[\"split\"](\"`\"); return aJAd5[\"reverse\"]().join(\"\");} else return \"" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\"/`*`@` `}`;`)`8`h`E`a`(`6`x`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`o`J`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\"/`*`@` `}`;`9`a`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`h" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\"/`*`@` `}`;`)`8`h`E`a`(`6`x`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDVy0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}