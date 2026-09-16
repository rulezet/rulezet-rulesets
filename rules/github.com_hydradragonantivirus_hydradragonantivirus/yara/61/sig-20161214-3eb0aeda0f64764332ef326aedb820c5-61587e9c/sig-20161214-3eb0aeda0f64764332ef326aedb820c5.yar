rule sig_20161214_3eb0aeda0f64764332ef326aedb820c5 {
  meta:
    description = "datamaliciousorder - file 20161214_3eb0aeda0f64764332ef326aedb820c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b56fcf54ddcb054deed9d24009962217e9d105f84e3c7554c70737bab8a2900a"

  strings:
    $s1  = "function aYXx0(aRs2) {eval(\"/*@cc_on var aCd4 = new Date() @*/\");aCd4[\"setUTCSeconds\"](\"0\", \"20\");if (aCd4.getUTCMillise" ascii
    $s2  = "function aYXx0(aRs2) {eval(\"/*@cc_on var aCd4 = new Date() @*/\");aCd4[\"setUTCSeconds\"](\"0\", \"20\");if (aCd4.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`t`A`K`a`=`2`y" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\"}`;`h`t`a`P`t`r`o`h`S`.`4`s`P`B`a` `n`r`u`t`e`r`;`)`2`y`Y`E" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `3" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`1`+`1`=`8`p`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\"/`*`@` `}`;`2`s`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`t`A`K`a`=`2`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`4`c`P`E`a` `+` `9`m`V`S`a`=`2`t`A`K`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`0` `=` `2`s`K`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\"/`*`@` `}`;`3`s`P`a` `n`r`u`t`e`r`;`}`;`)`3`a`K`a`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\"/`*`@` `}`;`)`5`d`T`a`(`5`m`I`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYXx0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}