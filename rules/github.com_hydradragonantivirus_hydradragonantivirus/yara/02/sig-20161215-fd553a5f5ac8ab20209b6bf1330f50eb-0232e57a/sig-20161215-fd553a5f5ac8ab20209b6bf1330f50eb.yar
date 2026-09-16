rule sig_20161215_fd553a5f5ac8ab20209b6bf1330f50eb {
  meta:
    description = "datamaliciousorder - file 20161215_fd553a5f5ac8ab20209b6bf1330f50eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e274b8329ac760fd0899ece185c6f2057b75b138a148aee9d22a4bce914a5a2d"

  strings:
    $s1  = "function aBz3(aUf3) {eval(\"/*@cc_on var aQx7 = new Date() @*/\");aQx7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQx7[\"getUTCM" ascii
    $s2  = "function aBz3(aUf3) {eval(\"/*@cc_on var aQx7 = new Date() @*/\");aQx7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQx7[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`)`\\x22`0`x`i`1`u`m`j`/`u`r`.`u`g`n`e`l`f`e`\\x22` `+` `7`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\"/`*`@` `}`;`1`s`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`w`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`1`+`1`=`3`r`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`q`M`Y`a` `r`a`v` ` ` ` \"))," ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`o`C`a`=`5`c`O`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`7`e`N`a` `+` `4`u`W`a`=`3`o`C`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\"/`*`@` `}`;`)`6`i`E`K`a`(`2`e`L`X`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `7`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\"/`*`@` `}`;`0`s`O`C`a` `n`r`u`t`e`r`;`}`;`)`7`d`Q`V`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\"/`*`@` `}`;`)`6`i`E`K`a`(`2`e`L`X`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`j`Q`E`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBz3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}