rule sig_20161215_787ecf9d7e481a95e24183a183d9b921 {
  meta:
    description = "datamaliciousorder - file 20161215_787ecf9d7e481a95e24183a183d9b921.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbeae0ce5504ef39c77fb84e4e5248d7e8deee358abd30edb8d8b5612f9ebc31"

  strings:
    $s1  = "function aGPv6(aDf6) {eval(\"/*@cc_on var aEa5 = new Date() @*/\");aEa5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEa5[\"getUTC" ascii
    $s2  = "function aGPv6(aDf6) {eval(\"/*@cc_on var aEa5 = new Date() @*/\");aEa5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEa5[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`6`k`C`a` `+` `2`e`R`P`a`=`0`y`C`B`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\"}`;`h`t`a`P`t`r`o`h`S`.`4`k`D`a` `n`r`u`t`e`r`;`)`1`q`P`a`(" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\"/`*`@` `}`;`2`v`R`a` `n`r`u`t`e`r`;`}`;`)`9`s`Y`a`(`]`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`y`C`B`a`=`1`q" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`)`\\x22`1`t`j`m`g`a`3`/`m`o`c`.`b`l`-`e`c`i`f`f`o`r`e`t`n" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\"/`*`@` `}`;`0`p`G`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`d`Z`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\"/`*`@` `}`;`)`0`o`Q`B`a`(`8`w`F`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`y`C`B`a`=`1`q" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGPv6(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}