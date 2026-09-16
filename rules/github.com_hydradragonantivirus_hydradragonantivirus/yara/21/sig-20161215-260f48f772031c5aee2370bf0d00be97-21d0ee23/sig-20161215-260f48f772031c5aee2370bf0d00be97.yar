rule sig_20161215_260f48f772031c5aee2370bf0d00be97 {
  meta:
    description = "datamaliciousorder - file 20161215_260f48f772031c5aee2370bf0d00be97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4a7988676e990fafe6da50dcf63ffeb2944be511d6913db2afd284e30618b6a"

  strings:
    $s1  = "function aBBg8(aYSb7) {eval(\"/*@cc_on var aZi7 = new Date() @*/\");aZi7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZi7[\"getUT" ascii
    $s2  = "function aBBg8(aYSb7) {eval(\"/*@cc_on var aZi7 = new Date() @*/\");aZi7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZi7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`0` `=` `8`f`Z`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s7  = "ds\"]()[\"toString\"](10) == \"20\") {var aEZw9 = aYSb7[\"split\"](\"`\"); return aEZw9[\"reverse\"]().join(\"\");} else return " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\"/`*`@` `}`;`7`b`S`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\"}`;`h`t`a`P`t`r`o`h`S`.`5`y`V`L`a` `n`r`u`t`e`r`;`)`5`n`S`F" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`a`A`Z`a` `r`a`v` ` ` ` \"))" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\"/`*`@` `}`;`9`w`Z`E`a` `n`r`u`t`e`r`;`}`;`)`1`g`G`X`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`l`O`a`=`5`n`S" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`e`T`a`;`)`2` `,`1`o`N`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`1`+`1`=`5`j`V`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBBg8(\";`)`\\x22`j`o`o`6`p`c`9`w`z`n`/`m`o`c`.`e`c`i`-`p`e`e`d`.`n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}