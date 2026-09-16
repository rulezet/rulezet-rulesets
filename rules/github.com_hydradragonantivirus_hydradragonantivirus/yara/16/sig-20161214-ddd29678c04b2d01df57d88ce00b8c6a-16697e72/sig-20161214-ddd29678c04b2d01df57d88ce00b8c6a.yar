rule sig_20161214_ddd29678c04b2d01df57d88ce00b8c6a {
  meta:
    description = "datamaliciousorder - file 20161214_ddd29678c04b2d01df57d88ce00b8c6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69bd1467fab654041ea57258b6ba44fc870a77bfbfdead3c72cd6c91df5ac8ed"

  strings:
    $s1  = "function aDk5(aVWm5) {eval(\"/*@cc_on var aBa9 = new Date() @*/\");aBa9[\"setUTCSeconds\"](\"0\", \"20\");if (aBa9.getUTCMillise" ascii
    $s2  = "function aDk5(aVWm5) {eval(\"/*@cc_on var aBa9 = new Date() @*/\");aBa9[\"setUTCSeconds\"](\"0\", \"20\");if (aBa9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`5`b`F`a` `+` `6`g`B`a`=`4`n`E`G`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "toString(10) == \"20\") {var aVv3 = aVWm5[\"split\"](\"`\"); return aVv3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`y`S`F`a` `n`r`u`t`e`r`;`)`2`r`N`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\"/`*`@` `}`;`5`m`W`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\"/`*`@` `}`;`)`7`l`U`a`(`3`j`Y`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\"/`*`@` `}`;`3`v`V`a` `n`r`u`t`e`r`;`}`;`)`6`a`H`a`(`]`\\x22`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`y`S`F`a` `n`r`u`t`e`r`;`)`2`r`N`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` `" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\"/`*`@` `}`;`4`i`E`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`1`+`1`=`9`l`Q`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `3`m`Y`a` `r`a`v` ` ` ` \")), 1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}