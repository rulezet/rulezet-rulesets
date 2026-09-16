rule sig_20161215_e27bc9b7801a60ec443eb99ac59131a9 {
  meta:
    description = "datamaliciousorder - file 20161215_e27bc9b7801a60ec443eb99ac59131a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b3ac4525a7a21e4a3cd852087eae2cb889357b3bce019876d076be62d95430b"

  strings:
    $s1  = "function aPq8(aLLy6) {eval(\"/*@cc_on var aVRe6 = new Date() @*/\");aVRe6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVRe6[\"get" ascii
    $s2  = "function aPq8(aLLy6) {eval(\"/*@cc_on var aVRe6 = new Date() @*/\");aVRe6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVRe6[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\"/`*`@` `}`;`)`1`h`E`a`(`0`k`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `5`k`K`J`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`0` `=` `2`z`A`E`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`d`P`B`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`y`C`a`;`)`2` `,`0`y`N`E`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\"/`*`@` `}`;`6`y`L`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\"/`*`@` `}`;`)`1`h`E`a`(`0`k`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `5`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`1`+`1`=`4`k`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\"\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPq8(\";`1`+`1`=`4`k`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}