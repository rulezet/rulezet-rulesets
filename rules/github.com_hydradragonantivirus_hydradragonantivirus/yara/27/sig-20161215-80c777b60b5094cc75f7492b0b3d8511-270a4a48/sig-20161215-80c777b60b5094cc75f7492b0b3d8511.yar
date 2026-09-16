rule sig_20161215_80c777b60b5094cc75f7492b0b3d8511 {
  meta:
    description = "datamaliciousorder - file 20161215_80c777b60b5094cc75f7492b0b3d8511.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00ab4c38d5b1ddb7690492b113604dd48a2dc6ba36454533084b393f43b9f696"

  strings:
    $s1  = "function aUKm7(aJCi0) {eval(\"/*@cc_on var aGs0 = new Date() @*/\");aGs0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGs0[\"getUT" ascii
    $s2  = "function aUKm7(aJCi0) {eval(\"/*@cc_on var aGs0 = new Date() @*/\");aGs0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGs0[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\"/`*`@` `}`;`3`v`J`a` `n`r`u`t`e`r`;`}`;`)`9`m`U`a`(`]`\\x22" ascii
    $s8  = "ds\"]()[\"toString\"](10) == \"20\") {var aJv3 = aJCi0[\"split\"](\"`\"); return aJv3[\"reverse\"]().join(\"\");} else return \"" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\"}`;`h`t`a`P`t`r`o`h`S`.`1`g`R`a` `n`r`u`t`e`r`;`)`5`b`L`G`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`j`N`D`a`;`)`2` `,`3`r`F`K`a`(" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`1`+`1`=`2`s`G`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`1`+`1`=`2`s`G`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`e`T`a`=`5`b`L" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\"/`*`@` `}`;`5`e`T`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`0` `=` `0`t`J`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\"/`*`@` `}`;`3`v`J`a` `n`r`u`t`e`r`;`}`;`)`9`m`U`a`(`]`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUKm7(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `2`c`P" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}