rule sig_20161214_9a9f1ba47a54a788024ce46270ccc3fe {
  meta:
    description = "datamaliciousorder - file 20161214_9a9f1ba47a54a788024ce46270ccc3fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac61e6845f1da339dece20a93ab72bcdf4d4e1ffdab1c335fa8e2a39919ca2a4"

  strings:
    $s1  = "function aRSn8(aGOf5) {eval(\"/*@cc_on var aFNz1 = new Date() @*/\");aFNz1[\"setUTCSeconds\"](\"0\", \"20\");if (aFNz1.getUTCMil" ascii
    $s2  = "function aRSn8(aGOf5) {eval(\"/*@cc_on var aFNz1 = new Date() @*/\");aFNz1[\"setUTCSeconds\"](\"0\", \"20\");if (aFNz1.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\"/`*`@` `}`;`5`f`O`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`5`y`Y`a` `+` `0`4`f`E`a`=`0`m`W`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\"/`*`@` `}`;`)`5`p`I`a`(`0`t`D`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`m`W`a`=`8`g`T" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\"/`*`@` `}`;`2`c`P`J`a` `n`r`u`t`e`r`;`}`;`)`4`e`N`H`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`v`V`a` `r`a`v` ` ` ` \")), " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\"/`*`@` `}`;`2`c`P`J`a` `n`r`u`t`e`r`;`}`;`)`4`e`N`H`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`m`W`a`=`8`g`T" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRSn8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}