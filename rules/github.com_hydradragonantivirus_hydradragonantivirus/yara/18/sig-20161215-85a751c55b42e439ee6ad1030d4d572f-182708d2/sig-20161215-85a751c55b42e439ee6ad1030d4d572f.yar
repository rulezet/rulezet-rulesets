rule sig_20161215_85a751c55b42e439ee6ad1030d4d572f {
  meta:
    description = "datamaliciousorder - file 20161215_85a751c55b42e439ee6ad1030d4d572f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf63d62c401d08ee0208c1aa2bfb3a86be6d89b1390f742e3887a684df73ba48"

  strings:
    $s1  = "function aBi7(aXYy4) {eval(\"/*@cc_on var aWo0 = new Date() @*/\");aWo0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWo0[\"getUTC" ascii
    $s2  = "function aBi7(aXYy4) {eval(\"/*@cc_on var aWo0 = new Date() @*/\");aWo0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWo0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`j`F`a` `r`a`v` ` ` ` \")), 1" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\"/`*`@` `}`;`6`o`W`a` `n`r`u`t`e`r`;`}`;`)`2`w`S`J`a`(`]`\\x2" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\"/`*`@` `}`;`2`t`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`l`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\"/`*`@` `}`;`)`3`f`Y`T`a`(`4`w`G`Z`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `3`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`1`+`1`=`4`e`T`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\"/`*`@` `}`;`4`y`Y`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`4`i`Q`D`a` `+` `2`p`B`F`a`=`5`c`Z`P`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`c`Z`P`a`=`1`g`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`1`+`1`=`4`e`T`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBi7(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}