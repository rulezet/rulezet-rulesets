rule sig_20161214_e069942fc3074c444fc7036da5880ae0 {
  meta:
    description = "datamaliciousorder - file 20161214_e069942fc3074c444fc7036da5880ae0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb22d6d1f9d0b6c614b79974c81eaf176b4c3b4de785b7621da9b701797d4ccb"

  strings:
    $s1  = "function aKTm4(aLc0) {eval(\"/*@cc_on var aQf2 = new Date() @*/\");aQf2[\"setUTCSeconds\"](\"0\", \"20\");if (aQf2.getUTCMillise" ascii
    $s2  = "function aKTm4(aLc0) {eval(\"/*@cc_on var aQf2 = new Date() @*/\");aQf2[\"setUTCSeconds\"](\"0\", \"20\");if (aQf2.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`p`J`T`a`;`)`2` `,`1`k`K`W`a`(" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\"/`*`@` `}`;`)`3`e`S`a`(`8`c`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`1`+`1`=`3`x`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`3`h`G`a` `+` `0`l`Y`K`a`=`9`t`Z`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\"/`*`@` `}`;`9`z`L`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1" ascii
    $s16 = "toString(10) == \"20\") {var aPd6 = aLc0[\"split\"](\"`\"); return aPd6.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`m`G`X`a` `r`a`v` ` ` ` \"))" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\"/`*`@` `}`;`0`c`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKTm4(\"/`*`@` `}`;`6`d`P`a` `n`r`u`t`e`r`;`}`;`)`0`y`J`L`a`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}