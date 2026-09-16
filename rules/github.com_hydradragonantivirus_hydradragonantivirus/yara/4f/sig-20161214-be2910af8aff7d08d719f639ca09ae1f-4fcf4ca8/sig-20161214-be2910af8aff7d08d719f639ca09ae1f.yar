rule sig_20161214_be2910af8aff7d08d719f639ca09ae1f {
  meta:
    description = "datamaliciousorder - file 20161214_be2910af8aff7d08d719f639ca09ae1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9865bdd81a7d098a80e301feb22c730fd9fee0fe6bfc896eb85e8a090b1ad96"

  strings:
    $s1  = "function aTWm2(aMe6) {eval(\"/*@cc_on var aHz8 = new Date() @*/\");aHz8[\"setUTCSeconds\"](\"0\", \"20\");if (aHz8.getUTCMillise" ascii
    $s2  = "function aTWm2(aMe6) {eval(\"/*@cc_on var aHz8 = new Date() @*/\");aHz8[\"setUTCSeconds\"](\"0\", \"20\");if (aHz8.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\"/`*`@` `}`;`2`i`Y`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\"/`*`@` `}`;`)`4`d`L`I`a`(`0`o`J`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s8  = "toString(10) == \"20\") {var aIQd2 = aMe6[\"split\"](\"`\"); return aIQd2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\"/`*`@` `}`;`6`e`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`g`T`a`=`3`f`C" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\"/`*`@` `}`;`)`4`d`L`I`a`(`0`o`J`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\"/`*`@` `}`;`2`d`Q`I`a` `n`r`u`t`e`r`;`}`;`)`4`o`D`Z`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTWm2(\";`0` `=` `0`s`H`M`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}