rule sig_20161214_a95ff7a8d94cc79df15b4870d1842277 {
  meta:
    description = "datamaliciousorder - file 20161214_a95ff7a8d94cc79df15b4870d1842277.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31ae01da3be29e29f4ba65b59422052b1f4a79a96f5b1c3d62e5fe4587918dc2"

  strings:
    $s1  = "function aPJw5(aCGd3) {eval(\"/*@cc_on var aPq2 = new Date() @*/\");aPq2[\"setUTCSeconds\"](\"0\", \"20\");if (aPq2.getUTCMillis" ascii
    $s2  = "function aPJw5(aCGd3) {eval(\"/*@cc_on var aPq2 = new Date() @*/\");aPq2[\"setUTCSeconds\"](\"0\", \"20\");if (aPq2.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`1`+`1`=`5`i`B`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`9`v`J`S`a` `+` `1`n`I`a`=`7`e`U`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`e`U`a`=`4`b`O" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\"/`*`@` `}`;`3`d`G`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = ".toString(10) == \"20\") {var aQQo3 = aCGd3[\"split\"](\"`\"); return aQQo3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`d`J`W`a` `n`r`u`t`e`r`;`)`4`b`O`Y" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`e`D`a`;`)`2` `,`6`i`Y`X`a`(`]" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`0` `=` `4`b`Y`A`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\"/`*`@` `}`;`3`j`U`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPJw5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}