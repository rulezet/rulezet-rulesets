rule sig_20161215_fa239f3d49e1bc9be1b0e72c8ddbe3fb {
  meta:
    description = "datamaliciousorder - file 20161215_fa239f3d49e1bc9be1b0e72c8ddbe3fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "630f8bf148c7ba322df5644cb79f45ef9bdb9f68d36933e49b96f93d09bceba2"

  strings:
    $s1  = "function aHNn9(aUBf4) {eval(\"/*@cc_on var aYEz0 = new Date() @*/\");aYEz0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYEz0[\"ge" ascii
    $s2  = "function aHNn9(aUBf4) {eval(\"/*@cc_on var aYEz0 = new Date() @*/\");aYEz0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYEz0[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`5`w`S`G`a` `+` `5`e`V`S`a`=`2`e`S`X`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\"/`*`@` `}`;`4`f`B`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\"/`*`@` `}`;`2`k`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`r" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\"/`*`@` `}`;`)`6`j`R`a`(`5`f`F`V`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`1`+`1`=`8`z`V`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `8`v`A" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\"/`*`@` `}`;`9`p`Q`W`a` `n`r`u`t`e`r`;`}`;`)`4`e`U`N`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`1`+`1`=`8`z`V`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNn9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`b`L`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}