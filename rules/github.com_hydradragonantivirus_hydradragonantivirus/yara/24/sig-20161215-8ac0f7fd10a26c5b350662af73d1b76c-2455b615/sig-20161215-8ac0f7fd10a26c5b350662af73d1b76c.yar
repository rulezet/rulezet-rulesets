rule sig_20161215_8ac0f7fd10a26c5b350662af73d1b76c {
  meta:
    description = "datamaliciousorder - file 20161215_8ac0f7fd10a26c5b350662af73d1b76c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768fba341c3798c1df0d32e21e5deabe55bd7ae183e724253354b860467cfed8"

  strings:
    $s1  = "function aPw6(aPQn4) {eval(\"/*@cc_on var aKk2 = new Date() @*/\");aKk2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKk2[\"getUTC" ascii
    $s2  = "function aPw6(aPQn4) {eval(\"/*@cc_on var aKk2 = new Date() @*/\");aKk2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKk2[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`b`B`R`a`;`)`2` `,`6`t`O`R`a`(`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\"/`*`@` `}`;`4`q`Y`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`b`I`a`=`4`v`D`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`0` `=` `9`z`H`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`v`O`I`a` `r`a`v` `;`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`)`\\x22`x`x`1`p`l`e`n`v`d`/`m`o`c`.`t`s`s`e`w`-`a`d`n`a`f`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`v`O`I`a` `r`a`v` `;`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`b`I`a`=`4`v`D`" ascii
    $s16 = "s\"]()[\"toString\"](10) == \"20\") {var aXw6 = aPQn4[\"split\"](\"`\"); return aXw6[\"reverse\"]().join(\"\");} else return \"" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\"/`*`@` `}`;`4`n`Q`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\"/`*`@` `}`;`4`q`Y`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPw6(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}