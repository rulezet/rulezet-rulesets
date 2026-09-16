rule sig_20161214_25716acc5591af613dfc381294e4f4dc {
  meta:
    description = "datamaliciousorder - file 20161214_25716acc5591af613dfc381294e4f4dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b5719bd409a86bd3d71b764d0984cd4115b3da0cdb6d9d8c34426796bb7b20c"

  strings:
    $s1  = "function aRs3(aEo8) {eval(\"/*@cc_on var aUe4 = new Date() @*/\");aUe4[\"setUTCSeconds\"](\"0\", \"20\");if (aUe4.getUTCMillisec" ascii
    $s2  = "function aRs3(aEo8) {eval(\"/*@cc_on var aUe4 = new Date() @*/\");aUe4[\"setUTCSeconds\"](\"0\", \"20\");if (aUe4.getUTCMillisec" ascii
    $s3  = "oString(10) == \"20\") {var aNRk4 = aEo8[\"split\"](\"`\"); return aNRk4.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`b`X`U`a` `n`r`u`t`e`r`;`)`3`b`H`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`1`+`1`=`1`a`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `9`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`0` `=` `6`q`T`C`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\"/`*`@` `}`;`4`k`R`N`a` `n`r`u`t`e`r`;`}`;`)`1`h`I`a`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`f`G`Z`a`=`3`b`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`c`W`N`a`;`)`2` `,`6`e`I`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`c`W`N`a`;`)`2` `,`6`e`I`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRs3(\"/`*`@` `}`;`2`w`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}