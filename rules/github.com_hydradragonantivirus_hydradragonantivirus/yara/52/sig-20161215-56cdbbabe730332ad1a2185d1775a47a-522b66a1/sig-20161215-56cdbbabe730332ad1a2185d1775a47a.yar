rule sig_20161215_56cdbbabe730332ad1a2185d1775a47a {
  meta:
    description = "datamaliciousorder - file 20161215_56cdbbabe730332ad1a2185d1775a47a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e6317e5a5c2820c873e473ab773911c84941a4dfb9a7668c065d76fde849745"

  strings:
    $s1  = "function aCQf1(aGi9) {eval(\"/*@cc_on var aSx9 = new Date() @*/\");aSx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSx9[\"getUTC" ascii
    $s2  = "function aCQf1(aGi9) {eval(\"/*@cc_on var aSx9 = new Date() @*/\");aSx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSx9[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`0` `=` `8`x`Z`Z`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`z`P`C`a`=`7`n" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\"}`;`h`t`a`P`t`r`o`h`S`.`0`n`C`S`a` `n`r`u`t`e`r`;`)`7`n`V`a" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `3" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`9`c`V`a` `+` `8`g`Y`a`=`4`z`P`C`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`1`+`1`=`0`k`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\"/`*`@` `}`;`)`7`p`Y`a`(`1`h`Q`T`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`j`S`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`e`L`a`;`)`2` `,`2`h`Q`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`e`L`a`;`)`2` `,`2`h`Q`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\"/`*`@` `}`;`)`7`p`Y`a`(`1`h`Q`T`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\"/`*`@` `}`;`9`i`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii
    $s19 = "s\"]()[\"toString\"](10) == \"20\") {var aVKt9 = aGi9[\"split\"](\"`\"); return aVKt9[\"reverse\"]().join(\"\");} else return \"" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQf1(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}