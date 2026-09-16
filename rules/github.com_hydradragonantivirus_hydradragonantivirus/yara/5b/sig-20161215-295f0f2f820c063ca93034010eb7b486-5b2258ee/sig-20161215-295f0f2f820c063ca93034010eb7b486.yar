rule sig_20161215_295f0f2f820c063ca93034010eb7b486 {
  meta:
    description = "datamaliciousorder - file 20161215_295f0f2f820c063ca93034010eb7b486.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3de0362b2cf59426bffb5b782b1bcaf97dc24c12d9010beaa8b596b617e09cd"

  strings:
    $s1  = "function aKb0(aRb4) {eval(\"/*@cc_on var aUQx7 = new Date() @*/\");aUQx7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUQx7[\"getU" ascii
    $s2  = "function aKb0(aRb4) {eval(\"/*@cc_on var aUQx7 = new Date() @*/\");aUQx7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUQx7[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\"/`*`@` `}`;`)`8`m`Q`a`(`9`r`G`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\"}`;`h`t`a`P`t`r`o`h`S`.`5`i`R`F`a` `n`r`u`t`e`r`;`)`3`r`Y`F`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\"/`*`@` `}`;`9`z`G`Z`a` `n`r`u`t`e`r`;`}`;`)`3`r`E`a`(`]`\\x2" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`k`J`a`;`)`2` `,`2`a`M`H`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\"/`*`@` `}`;`1`c`X`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "nds\"]()[\"toString\"](10) == \"20\") {var aZGz9 = aRb4[\"split\"](\"`\"); return aZGz9[\"reverse\"]().join(\"\");} else return " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\"}`;`h`t`a`P`t`r`o`h`S`.`5`i`R`F`a` `n`r`u`t`e`r`;`)`3`r`Y`F`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`q`S`a` `r`a`v` `;`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\"/`*`@` `}`;`4`b`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKb0(\";`8`e`N`M`a` `+` `3`x`B`a`=`8`f`H`H`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}