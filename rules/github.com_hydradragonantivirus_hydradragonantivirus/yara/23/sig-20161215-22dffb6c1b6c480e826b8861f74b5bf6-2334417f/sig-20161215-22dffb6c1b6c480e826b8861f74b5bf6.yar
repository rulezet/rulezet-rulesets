rule sig_20161215_22dffb6c1b6c480e826b8861f74b5bf6 {
  meta:
    description = "datamaliciousorder - file 20161215_22dffb6c1b6c480e826b8861f74b5bf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "691348abdcc920dc0ac27992b831ba9224f57d8bd0dfd55b7077a953718bc661"

  strings:
    $s1  = "function aYSf4(aUc9) {eval(\"/*@cc_on var aKVo4 = new Date() @*/\");aKVo4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKVo4[\"get" ascii
    $s2  = "function aYSf4(aUc9) {eval(\"/*@cc_on var aKVo4 = new Date() @*/\");aKVo4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKVo4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\"/`*`@` `}`;`)`7`z`B`U`a`(`0`t`C`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\"/`*`@` `}`;`9`c`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\"}`;`h`t`a`P`t`r`o`h`S`.`7`z`A`a` `n`r`u`t`e`r`;`)`6`p`I`F`a" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`e`J`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`p`O`W`a`=`6`p" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\"/`*`@` `}`;`5`v`U`W`a` `n`r`u`t`e`r`;`}`;`)`9`s`B`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`)`\\x22`c`g`o`m`v`a`k`4`t`/`n`c`.`k`r`o`w`t`a`\\x22` `+` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\"/`*`@` `}`;`)`7`z`B`U`a`(`0`t`C`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\"/`*`@` `}`;`9`c`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`1`+`1`=`1`t`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYSf4(\"/`*`@` `}`;`1`i`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`t" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}