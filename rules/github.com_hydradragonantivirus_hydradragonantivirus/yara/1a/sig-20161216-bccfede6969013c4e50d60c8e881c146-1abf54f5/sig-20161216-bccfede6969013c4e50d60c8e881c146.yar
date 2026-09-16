rule sig_20161216_bccfede6969013c4e50d60c8e881c146 {
  meta:
    description = "datamaliciousorder - file 20161216_bccfede6969013c4e50d60c8e881c146.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7b4d563d46c580ab8e14d25b603f04595fafac249caa76a0423347dc0e0a44a"

  strings:
    $s1  = "function aBWz6(aSm5) {eval(\"/*@cc_on var aIKf4 = new Date() @*/\");aIKf4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIKf4[\"get" ascii
    $s2  = "function aBWz6(aSm5) {eval(\"/*@cc_on var aIKf4 = new Date() @*/\");aIKf4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIKf4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\"/`*`@` `}`;`5`m`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`s`F`A`a` `r`a`v` `;" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`)`\\x22`d`m`w`f`r`/`z`c`.`n`g`i`s`e`d`y`t`t`e`b`\\x22` `+" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`d`S`a`;`)`2` `,`9`l`R`a`(`]`" ascii
    $s7  = "onds\"]()[\"toString\"](10) == \"20\") {var aHWf2 = aSm5[\"split\"](\"`\"); return aHWf2[\"reverse\"]().join(\"\");} else return" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`a`U`a` `n`r`u`t`e`r`;`)`5`k`M`R`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `6`g`X`W" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\"/`*`@` `}`;`)`7`a`C`a`(`7`y`T`B`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\"/`*`@` `}`;`2`f`W`H`a` `n`r`u`t`e`r`;`}`;`)`4`i`O`a`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`1`+`1`=`4`i`K`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\"/`*`@` `}`;`2`f`W`H`a` `n`r`u`t`e`r`;`}`;`)`4`i`O`a`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`)`\\x22`d`m`w`f`r`/`z`c`.`n`g`i`s`e`d`y`t`t`e`b`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\"/`*`@` `}`;`4`v`S`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`a`U`a` `n`r`u`t`e`r`;`)`5`k`M`R`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWz6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}