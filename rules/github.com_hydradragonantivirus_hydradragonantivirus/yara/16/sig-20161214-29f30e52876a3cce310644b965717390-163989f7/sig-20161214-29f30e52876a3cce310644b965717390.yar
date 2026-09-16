rule sig_20161214_29f30e52876a3cce310644b965717390 {
  meta:
    description = "datamaliciousorder - file 20161214_29f30e52876a3cce310644b965717390.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1fe069ebcd939f801543faf1ec1f8d505cea65a5a33033dfe27c5464253cd03"

  strings:
    $s1  = "function aKMn4(aOUb7) {eval(\"/*@cc_on var aOu3 = new Date() @*/\");aOu3[\"setUTCSeconds\"](\"0\", \"20\");if (aOu3.getUTCMillis" ascii
    $s2  = "function aKMn4(aOUb7) {eval(\"/*@cc_on var aOu3 = new Date() @*/\");aOu3[\"setUTCSeconds\"](\"0\", \"20\");if (aOu3.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`0` `=` `8`b`E`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`o`G`a`;`)`2` `,`1`v`D`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\"/`*`@` `}`;`0`j`W`a` `n`r`u`t`e`r`;`}`;`)`8`z`Y`a`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`1`+`1`=`0`a`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`m`I`L`a`=`7`x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\"/`*`@` `}`;`1`i`P`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`1`+`1`=`0`a`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\"}`;`h`t`a`P`t`r`o`h`S`.`3`m`K`a` `n`r`u`t`e`r`;`)`7`x`U`a`(" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKMn4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = ".toString(10) == \"20\") {var aWj0 = aOUb7[\"split\"](\"`\"); return aWj0.reverse().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}