rule sig_20161215_15279ad5cdaddc298d974c5fcf31344b {
  meta:
    description = "datamaliciousorder - file 20161215_15279ad5cdaddc298d974c5fcf31344b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "634a4bc41aebce2a63d970277729feb5decc2df3db88a82c4dd25c39008860ef"

  strings:
    $s1  = "function aCSe5(aZq6) {eval(\"/*@cc_on var aTr1 = new Date() @*/\");aTr1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTr1[\"getUTC" ascii
    $s2  = "function aCSe5(aZq6) {eval(\"/*@cc_on var aTr1 = new Date() @*/\");aTr1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTr1[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`1`+`1`=`9`r`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s4  = "s\"]()[\"toString\"](10) == \"20\") {var aPc2 = aZq6[\"split\"](\"`\"); return aPc2[\"reverse\"]().join(\"\");} else return \"\"" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`r`J`Q`a` `n`r`u`t`e`r`;`)`2`m`M`a" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\"/`*`@` `}`;`2`c`P`a` `n`r`u`t`e`r`;`}`;`)`4`s`R`Y`a`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`r`S`A`a`=`2`m" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`1`+`1`=`9`r`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\"/`*`@` `}`;`6`q`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`g`A`G`a` `r`a`v` ` ` ` \"))" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\"/`*`@` `}`;`)`5`n`F`Y`a`(`0`q`O`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSe5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`r`J`Q`a` `n`r`u`t`e`r`;`)`2`m`M`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}