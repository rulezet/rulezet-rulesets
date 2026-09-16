rule sig_20161215_e989db9b1e0685bfa42a9ed35afa6800 {
  meta:
    description = "datamaliciousorder - file 20161215_e989db9b1e0685bfa42a9ed35afa6800.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66eb729bcd7d30ac63bed93c1dbe389190122265bfc07e60b4342a036102a57c"

  strings:
    $s1  = "function aGx9(aNIf0) {eval(\"/*@cc_on var aQZh5 = new Date() @*/\");aQZh5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQZh5[\"get" ascii
    $s2  = "function aGx9(aNIf0) {eval(\"/*@cc_on var aQZh5 = new Date() @*/\");aQZh5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQZh5[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`.`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`1`+`1`=`6`f`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`i`A`I`a` `r`a`v` ` ` ` \"))," ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\"/`*`@` `}`;`)`6`z`N`a`(`0`s`O`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\"}`;`h`t`a`P`t`r`o`h`S`.`1`g`D`A`a` `n`r`u`t`e`r`;`)`3`v`C`D`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`q`W`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\"/`*`@` `}`;`8`y`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`x`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`)`\\x22`1`t`j`m`g`a`3`/`m`o`c`.`b`l`-`e`c`i`f`f`o`r`e`t`n`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `8`v`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`9`z`G`E`a` `+` `2`c`X`a`=`5`w`C`J`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`w`C`J`a`=`3`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\"/`*`@` `}`;`2`k`T`X`a` `n`r`u`t`e`r`;`}`;`)`3`i`Y`N`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGx9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}