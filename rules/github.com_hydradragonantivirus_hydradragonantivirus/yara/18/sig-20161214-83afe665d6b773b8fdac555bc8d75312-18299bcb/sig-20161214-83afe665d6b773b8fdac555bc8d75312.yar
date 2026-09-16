rule sig_20161214_83afe665d6b773b8fdac555bc8d75312 {
  meta:
    description = "datamaliciousorder - file 20161214_83afe665d6b773b8fdac555bc8d75312.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "734dac575342890aabb1fa32e30c41b6b8d02c70b8b5bff1ab7113155f560f14"

  strings:
    $s1  = "function aWCo7(aBl1) {eval(\"/*@cc_on var aOe5 = new Date() @*/\");aOe5[\"setUTCSeconds\"](\"0\", \"20\");if (aOe5.getUTCMillise" ascii
    $s2  = "function aWCo7(aBl1) {eval(\"/*@cc_on var aOe5 = new Date() @*/\");aOe5[\"setUTCSeconds\"](\"0\", \"20\");if (aOe5.getUTCMillise" ascii
    $s3  = "toString(10) == \"20\") {var aOMz8 = aBl1[\"split\"](\"`\"); return aOMz8.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `6`a`J`a`(`h" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`u`C`a`;`)`2` `,`1`l`E`V`a`(`]" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `6`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\"/`*`@` `}`;`1`l`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\"}`;`h`t`a`P`t`r`o`h`S`.`8`o`I`H`a` `n`r`u`t`e`r`;`)`4`w`Z`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\"/`*`@` `}`;`)`9`r`N`D`a`(`5`t`X`L`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`i`X`E`a`=`4`w" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\"/`*`@` `}`;`5`q`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`j" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWCo7(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}