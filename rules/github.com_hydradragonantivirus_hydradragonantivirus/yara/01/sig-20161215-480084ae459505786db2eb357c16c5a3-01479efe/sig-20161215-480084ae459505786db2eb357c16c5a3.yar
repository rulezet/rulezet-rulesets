rule sig_20161215_480084ae459505786db2eb357c16c5a3 {
  meta:
    description = "datamaliciousorder - file 20161215_480084ae459505786db2eb357c16c5a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cc28e27d5c4096f561ffc2bfb4e286c41a43615e11e0fac3c21727750fc6e17"

  strings:
    $s1  = "function aLZq2(aGl0) {eval(\"/*@cc_on var aGJx9 = new Date() @*/\");aGJx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGJx9[\"get" ascii
    $s2  = "function aLZq2(aGl0) {eval(\"/*@cc_on var aGJx9 = new Date() @*/\");aGJx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGJx9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\"/`*`@` `}`;`)`9`e`O`Q`a`(`2`i`E`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\"/`*`@` `}`;`5`u`J`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`0` `=` `3`h`A`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`l`L`Z`a` `r`a`v` `;" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `6`q" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`j`Y`a`;`)`2` `,`2`q`B`F`a`(`]" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`r`A`a`=`1`n`B" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\"/`*`@` `}`;`0`m`J`a` `n`r`u`t`e`r`;`}`;`)`4`c`M`E`a`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\"}`;`h`t`a`P`t`r`o`h`S`.`8`m`X`J`a` `n`r`u`t`e`r`;`)`1`n`B`I" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `6" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\"/`*`@` `}`;`0`l`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLZq2(\";`1`+`1`=`4`s`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}