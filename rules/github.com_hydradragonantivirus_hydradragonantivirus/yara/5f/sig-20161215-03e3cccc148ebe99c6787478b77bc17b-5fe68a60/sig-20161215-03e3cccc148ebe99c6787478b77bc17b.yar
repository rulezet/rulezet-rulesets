rule sig_20161215_03e3cccc148ebe99c6787478b77bc17b {
  meta:
    description = "datamaliciousorder - file 20161215_03e3cccc148ebe99c6787478b77bc17b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "353cfe9e089b30ba016c0fbb5f665718175abdb8617c100db4a32ac18174daef"

  strings:
    $s1  = "function aIPo8(aSSj7) {eval(\"/*@cc_on var aXDc1 = new Date() @*/\");aXDc1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXDc1[\"ge" ascii
    $s2  = "function aIPo8(aSSj7) {eval(\"/*@cc_on var aXDc1 = new Date() @*/\");aXDc1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXDc1[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\"/`*`@` `}`;`7`j`S`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\"/`*`@` `}`;`9`b`D`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`1`+`1`=`9`i`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\"/`*`@` `}`;`)`1`j`X`D`a`(`7`g`C`Y`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`t`B`a` `r`a`v` ` ` ` \")), " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\"/`*`@` `}`;`)`1`j`X`D`a`(`7`g`C`Y`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`1`+`1`=`9`i`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\"/`*`@` `}`;`7`w`U`a` `n`r`u`t`e`r`;`}`;`)`1`k`U`Y`a`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\"}`;`h`t`a`P`t`r`o`h`S`.`1`h`K`D`a` `n`r`u`t`e`r`;`)`8`b`O`a" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\";`8`l`H`a` `+` `0`s`J`a`=`6`j`C`O`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPo8(\"/`*`@` `}`;`7`w`U`a` `n`r`u`t`e`r`;`}`;`)`1`k`U`Y`a`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}