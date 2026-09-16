rule sig_20161215_2a614bab5eb5ff4b624e3f3f7ff133a0 {
  meta:
    description = "datamaliciousorder - file 20161215_2a614bab5eb5ff4b624e3f3f7ff133a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "567470c8910e1adf4c79321fba99916598b7afff92a3d522ce833efbfeb99875"

  strings:
    $s1  = "function aAKi5(aMj0) {eval(\"/*@cc_on var aWd9 = new Date() @*/\");aWd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWd9[\"getUTC" ascii
    $s2  = "function aAKi5(aMj0) {eval(\"/*@cc_on var aWd9 = new Date() @*/\");aWd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWd9[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"/`*`@` `}`;`0`j`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"/`*`@` `}`;`6`k`U`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"/`*`@` `}`;`)`5`j`V`a`(`4`v`Y`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`t`S`L`a`=`0`l" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`)`\\x22`j`o`o`6`p`c`9`w`z`n`/`m`o`c`.`e`c`i`-`p`e`e`d`.`n" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`)`\\x22`n`z`i`c`m`h`2`m`/`m`o`c`.`p`a`s`a`k`n`a`k`a`t`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`8`x`W`a` `+` `1`n`W`a`=`6`t`S`L`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"}`;`h`t`a`P`t`r`o`h`S`.`6`o`U`a` `n`r`u`t`e`r`;`)`0`l`V`C`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"/`*`@` `}`;`9`z`L`C`a` `n`r`u`t`e`r`;`}`;`)`9`x`E`P`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`t`W`P`a`;`)`2` `,`0`x`T`a`(`]" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAKi5(\"/`*`@` `}`;`6`k`U`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}