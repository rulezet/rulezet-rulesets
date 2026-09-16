rule sig_20161214_9c9ded70ca96213c0e635794f1843092 {
  meta:
    description = "datamaliciousorder - file 20161214_9c9ded70ca96213c0e635794f1843092.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0d3ede316267632d982044e4ac93d23a1d0926ec387d9c400df00432b68067f"

  strings:
    $s1  = "function aHk5(aYn0) {eval(\"/*@cc_on var aTAm2 = new Date() @*/\");aTAm2[\"setUTCSeconds\"](\"0\", \"20\");if (aTAm2.getUTCMilli" ascii
    $s2  = "function aHk5(aYn0) {eval(\"/*@cc_on var aTAm2 = new Date() @*/\");aTAm2[\"setUTCSeconds\"](\"0\", \"20\");if (aTAm2.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+`" ascii
    $s4  = ").toString(10) == \"20\") {var aCNc4 = aYn0[\"split\"](\"`\"); return aCNc4.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\"/`*`@` `}`;`0`n`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`r`M`L`a`=`4`x`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`1`+`1`=`7`u`C`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\"/`*`@` `}`;`4`c`N`C`a` `n`r`u`t`e`r`;`}`;`)`8`r`H`O`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\"/`*`@` `}`;`)`7`z`Y`a`(`6`q`A`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `0`c`S`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\"}`;`h`t`a`P`t`r`o`h`S`.`0`n`K`H`a` `n`r`u`t`e`r`;`)`4`x`Q`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHk5(\"}`;`h`t`a`P`t`r`o`h`S`.`0`n`K`H`a` `n`r`u`t`e`r`;`)`4`x`Q`a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}