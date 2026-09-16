rule sig_20161215_a1929a6094b0876a84b15311ecd40edd {
  meta:
    description = "datamaliciousorder - file 20161215_a1929a6094b0876a84b15311ecd40edd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128f2db275d4426abe09154d8a4e8f16cbdd945cca2065309166bf35e1d7dd2d"

  strings:
    $s1  = "function aPUv0(aTQo9) {eval(\"/*@cc_on var aHs1 = new Date() @*/\");aHs1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHs1[\"getUT" ascii
    $s2  = "function aPUv0(aTQo9) {eval(\"/*@cc_on var aHs1 = new Date() @*/\");aHs1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHs1[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`1`+`1`=`0`e`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`g`H`a` `n`r`u`t`e`r`;`)`1`q`G`O`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`1`+`1`=`0`e`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\"/`*`@` `}`;`)`9`w`P`Z`a`(`6`u`T`S`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\"/`*`@` `}`;`3`a`W`W`a` `n`r`u`t`e`r`;`}`;`)`2`d`M`a`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`g`H`a` `n`r`u`t`e`r`;`)`1`q`G`O`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\"/`*`@` `}`;`9`o`Q`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`3`t`Z`Y`a` `+` `9`n`S`S`a`=`7`g`W`V`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`h`X`B`a` `r`a`v` `;" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\"/`*`@` `}`;`6`m`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`f" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `3`e`J`U`a` `r`a`v` ` ` ` \"))" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`g`W`V`a`=`1`q" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPUv0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}