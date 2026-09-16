rule sig_20161214_2696ce0e4f99c8989f60808c23ec1663 {
  meta:
    description = "datamaliciousorder - file 20161214_2696ce0e4f99c8989f60808c23ec1663.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9f78f1e74b71b90327e1de0cf9a9e60c2083ac6e7f4de1c6951ff253bc227d6"

  strings:
    $s1  = "function aBu8(aQc6) {eval(\"/*@cc_on var aAFk5 = new Date() @*/\");aAFk5[\"setUTCSeconds\"](\"0\", \"20\");if (aAFk5.getUTCMilli" ascii
    $s2  = "function aBu8(aQc6) {eval(\"/*@cc_on var aAFk5 = new Date() @*/\");aAFk5[\"setUTCSeconds\"](\"0\", \"20\");if (aAFk5.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\"/`*`@` `}`;`4`y`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`j`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`a`D`E`a`=`3`g`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\"/`*`@` `}`;`)`2`r`R`a`(`7`n`V`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`m`K`a`(`h`" ascii
    $s10 = ").toString(10) == \"20\") {var aSNy7 = aQc6[\"split\"](\"`\"); return aSNy7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\"/`*`@` `}`;`7`y`N`S`a` `n`r`u`t`e`r`;`}`;`)`7`v`B`E`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `5`m`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\"/`*`@` `}`;`6`c`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`i`O`a`;`)`2` `,`2`c`L`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\"}`;`h`t`a`P`t`r`o`h`S`.`0`q`S`C`a` `n`r`u`t`e`r`;`)`3`g`S`S`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBu8(\";`0` `=` `3`w`G`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}