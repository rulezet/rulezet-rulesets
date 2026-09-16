rule sig_20161214_290599b77aefa4ff1823f7120c643024 {
  meta:
    description = "datamaliciousorder - file 20161214_290599b77aefa4ff1823f7120c643024.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74f057477f4d7f3e805301fe3db2afcf8c5cd44033f8c2d6246d8ecc7befcb2e"

  strings:
    $s1  = "function aOHf7(aEFi1) {eval(\"/*@cc_on var aRv2 = new Date() @*/\");aRv2[\"setUTCSeconds\"](\"0\", \"20\");if (aRv2.getUTCMillis" ascii
    $s2  = "function aOHf7(aEFi1) {eval(\"/*@cc_on var aRv2 = new Date() @*/\");aRv2[\"setUTCSeconds\"](\"0\", \"20\");if (aRv2.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`e`P`a`=`9`t`X" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `4`j" ascii
    $s5  = ".toString(10) == \"20\") {var aMKf9 = aEFi1[\"split\"](\"`\"); return aMKf9.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`u`H`a` `r`a`v` ` ` ` \")), " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`e`P`a`=`9`t`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\"/`*`@` `}`;`2`z`S`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`1`+`1`=`4`k`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`r`N`a`;`)`2` `,`4`q`H`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\"/`*`@` `}`;`2`z`S`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\"/`*`@` `}`;`1`i`F`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\";`0` `=` `7`k`C`C`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHf7(\"}`;`h`t`a`P`t`r`o`h`S`.`2`y`K`a` `n`r`u`t`e`r`;`)`9`t`X`a`(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}