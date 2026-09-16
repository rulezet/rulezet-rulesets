rule sig_20161215_7bc332f0a7eabbdb1820927dfaf425ba {
  meta:
    description = "datamaliciousorder - file 20161215_7bc332f0a7eabbdb1820927dfaf425ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e477e96f479ef014a0f619e1937f7ffffc2e2900cb96f670b902625c78c309e"

  strings:
    $s1  = "function aJp1(aGSp9) {eval(\"/*@cc_on var aBVy9 = new Date() @*/\");aBVy9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBVy9[\"get" ascii
    $s2  = "function aJp1(aGSp9) {eval(\"/*@cc_on var aBVy9 = new Date() @*/\");aBVy9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBVy9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`f`Q`Q`a`=`0`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\"/`*`@` `}`;`)`0`z`M`a`(`6`w`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`4`g`L`a` `+` `8`o`E`a`=`3`f`Q`Q`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "onds\"]()[\"toString\"](10) == \"20\") {var aZt6 = aGSp9[\"split\"](\"`\"); return aZt6[\"reverse\"]().join(\"\");} else return " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`k`H`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\"/`*`@` `}`;`6`t`Z`a` `n`r`u`t`e`r`;`}`;`)`0`v`X`B`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`)`\\x22`h`k`m`s`y`2`4`b`t`f`/`t`e`n`.`u`t`n`a`u`h`c`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\"/`*`@` `}`;`9`p`S`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`)`\\x22`x`x`1`p`l`e`n`v`d`/`m`o`c`.`t`s`s`e`w`-`a`d`n`a`f`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\"/`*`@` `}`;`6`t`Z`a` `n`r`u`t`e`r`;`}`;`)`0`v`X`B`a`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\"/`*`@` `}`;`7`q`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`z`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJp1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`q`Y`A`a`;`)`2` `,`1`e`W`R`a`(`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}