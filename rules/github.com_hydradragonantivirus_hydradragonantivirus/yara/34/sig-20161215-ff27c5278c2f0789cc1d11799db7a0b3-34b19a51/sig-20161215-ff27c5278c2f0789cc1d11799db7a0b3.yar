rule sig_20161215_ff27c5278c2f0789cc1d11799db7a0b3 {
  meta:
    description = "datamaliciousorder - file 20161215_ff27c5278c2f0789cc1d11799db7a0b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96eaa19fb8a2070d6066cf56e4caad5f7af86e7078c9871a07c50d180eb48eb8"

  strings:
    $s1  = "function aCJz6(aZq5) {eval(\"/*@cc_on var aLXp4 = new Date() @*/\");aLXp4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLXp4[\"get" ascii
    $s2  = "function aCJz6(aZq5) {eval(\"/*@cc_on var aLXp4 = new Date() @*/\");aLXp4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLXp4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`s`Z`K`a`=`0`u" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `4" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\"/`*`@` `}`;`6`a`B`N`a` `n`r`u`t`e`r`;`}`;`)`8`p`G`D`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`c`M`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\"/`*`@` `}`;`5`q`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`)`\\x22`g`v`j`j`y`/`m`o`c`.`c`e`l`e`s`e`k`y`d`\\x22` `+` " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`d`O`a`;`)`2` `,`5`a`C`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\"}`;`h`t`a`P`t`r`o`h`S`.`0`t`B`T`a` `n`r`u`t`e`r`;`)`0`u`K`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `4`q" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`c`M`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCJz6(\";`)`\\x22`g`v`j`j`y`/`m`o`c`.`c`e`l`e`s`e`k`y`d`\\x22` `+` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}