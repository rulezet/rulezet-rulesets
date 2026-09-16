rule sig_20161215_da5062f3f12134d14e12a82ad2928989 {
  meta:
    description = "datamaliciousorder - file 20161215_da5062f3f12134d14e12a82ad2928989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fe99994b0bbdbfeaf756168dcaab5c1305f55afefabd3cc4daffd45f56a190e"

  strings:
    $s1  = "function aKHu6(aQHw9) {eval(\"/*@cc_on var aXn7 = new Date() @*/\");aXn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXn7[\"getUT" ascii
    $s2  = "function aKHu6(aQHw9) {eval(\"/*@cc_on var aXn7 = new Date() @*/\");aXn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXn7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`n`R`a` `r`a`v` `;`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"/`*`@` `}`;`9`w`C`T`a` `n`r`u`t`e`r`;`}`;`)`6`x`A`E`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"/`*`@` `}`;`8`v`Y`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"/`*`@` `}`;`9`w`C`T`a` `n`r`u`t`e`r`;`}`;`)`6`x`A`E`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "ds\"]()[\"toString\"](10) == \"20\") {var aTCw9 = aQHw9[\"split\"](\"`\"); return aTCw9[\"reverse\"]().join(\"\");} else return " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`r`D`X`a`;`)`2` `,`9`z`J`S`a`(" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\";`1`+`1`=`3`o`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"/`*`@` `}`;`)`6`o`G`R`a`(`4`z`E`M`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"}`;`h`t`a`P`t`r`o`h`S`.`1`w`E`a` `n`r`u`t`e`r`;`)`2`i`M`G`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\"/`*`@` `}`;`8`v`Y`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKHu6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}