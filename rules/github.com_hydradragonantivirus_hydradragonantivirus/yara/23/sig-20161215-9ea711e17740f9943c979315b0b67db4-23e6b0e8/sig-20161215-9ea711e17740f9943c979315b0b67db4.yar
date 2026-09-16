rule sig_20161215_9ea711e17740f9943c979315b0b67db4 {
  meta:
    description = "datamaliciousorder - file 20161215_9ea711e17740f9943c979315b0b67db4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da8d3f34010519b09287b049c4af9615728426957f7e1f153f41f3c6a0b7cb58"

  strings:
    $s1  = "function aMj3(aFw1) {eval(\"/*@cc_on var aTb0 = new Date() @*/\");aTb0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTb0[\"getUTCM" ascii
    $s2  = "function aMj3(aFw1) {eval(\"/*@cc_on var aTb0 = new Date() @*/\");aTb0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTb0[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`z`U`Z`a`;`)`2` `,`5`m`R`L`a`(`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`r`G`W`a` `r`a`v` ` ` ` \"))," ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`m`A`a` `n`r`u`t`e`r`;`)`8`j`Y`B`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`z`U`Z`a`;`)`2` `,`5`m`R`L`a`(`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`m`A`a` `n`r`u`t`e`r`;`)`8`j`Y`B`a`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\"/`*`@` `}`;`1`w`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `5`s`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`1`+`1`=`5`g`E`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\"/`*`@` `}`;`)`3`m`G`E`a`(`3`t`I`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`1`+`1`=`5`g`E`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`a`Q`Y`a`=`8`j`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\"/`*`@` `}`;`0`f`G`a` `n`r`u`t`e`r`;`}`;`)`1`q`U`a`(`]`\\x22`" ascii
    $s19 = "\"]()[\"toString\"](10) == \"20\") {var aGf0 = aFw1[\"split\"](\"`\"); return aGf0[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMj3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`a`Q`Y`a`=`8`j`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}