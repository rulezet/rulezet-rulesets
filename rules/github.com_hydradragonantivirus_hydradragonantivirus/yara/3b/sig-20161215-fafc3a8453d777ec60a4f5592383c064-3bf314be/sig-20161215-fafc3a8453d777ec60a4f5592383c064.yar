rule sig_20161215_fafc3a8453d777ec60a4f5592383c064 {
  meta:
    description = "datamaliciousorder - file 20161215_fafc3a8453d777ec60a4f5592383c064.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e7a615bda6550b02ebf269c65aa789a3f8f2cfbed9d10d5bc00d54c7a5cb210"

  strings:
    $s1  = "function aXx4(aWAs3) {eval(\"/*@cc_on var aAZt2 = new Date() @*/\");aAZt2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAZt2[\"get" ascii
    $s2  = "function aXx4(aWAs3) {eval(\"/*@cc_on var aAZt2 = new Date() @*/\");aAZt2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAZt2[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`x`B`H`a`=`7`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`d`A`E`a` `r`a`v` `;`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\"/`*`@` `}`;`8`j`O`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`u`L`a`;`)`2` `,`8`d`N`O`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` `" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\"/`*`@` `}`;`)`5`s`U`H`a`(`6`d`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`u`L`a`;`)`2` `,`8`d`N`O`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`t`X`a` `r`a`v` ` ` ` \")), 1" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx4(\"/`*`@` `}`;`5`f`U`a` `n`r`u`t`e`r`;`}`;`)`3`u`A`H`a`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}