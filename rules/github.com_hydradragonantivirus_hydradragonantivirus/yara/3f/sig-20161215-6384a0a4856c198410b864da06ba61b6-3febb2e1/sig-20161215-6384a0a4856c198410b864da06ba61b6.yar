rule sig_20161215_6384a0a4856c198410b864da06ba61b6 {
  meta:
    description = "datamaliciousorder - file 20161215_6384a0a4856c198410b864da06ba61b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1abca0c321b14e702e8ace6ca9d00a969b25acb9029530d69fc5ae6c0dfafbb8"

  strings:
    $s1  = "function aLLv5(aMHi4) {eval(\"/*@cc_on var aEe7 = new Date() @*/\");aEe7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEe7[\"getUT" ascii
    $s2  = "function aLLv5(aMHi4) {eval(\"/*@cc_on var aEe7 = new Date() @*/\");aEe7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEe7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`c`K`a`;`)`2` `,`4`b`T`I`a`(`]" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`5`j`A`C`a` `+` `0`i`A`F`a`=`7`n`R`N`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`)`\\x22`d`w`n`h`3`c`m`/`m`o`c`.`i`a`i`d`u`w`\\x22` `+` `1" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`)`\\x22`m`f`a`6`0`v`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`t`n" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\"}`;`h`t`a`P`t`r`o`h`S`.`9`e`P`a` `n`r`u`t`e`r`;`)`8`o`E`W`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\"/`*`@` `}`;`9`c`F`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`)`\\x22`e`m`n`n`6`o`t`/`g`r`o`.`r`e`d`o`u`c`\\x22` `+` `1" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`)`\\x22`e`m`n`n`6`o`t`/`g`r`o`.`r`e`d`o`u`c`\\x22` `+` `1" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`a`L`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\"/`*`@` `}`;`3`h`K`E`a` `n`r`u`t`e`r`;`}`;`)`0`a`K`a`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`)`\\x22`j`v`n`x`u`/`p`j`.`9`1`1`a`m`a`\\x22` `+` `1`r`V`a" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLLv5(\"}`;`h`t`a`P`t`r`o`h`S`.`9`e`P`a` `n`r`u`t`e`r`;`)`8`o`E`W`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}