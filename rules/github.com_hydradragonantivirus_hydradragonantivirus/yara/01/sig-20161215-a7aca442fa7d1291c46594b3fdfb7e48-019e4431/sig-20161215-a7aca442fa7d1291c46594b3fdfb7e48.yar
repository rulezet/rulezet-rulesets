rule sig_20161215_a7aca442fa7d1291c46594b3fdfb7e48 {
  meta:
    description = "datamaliciousorder - file 20161215_a7aca442fa7d1291c46594b3fdfb7e48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "719a522a80cc92c50d249777d18d7db4922318bb6613615fb9d65ce7444260bf"

  strings:
    $s1  = "function aFa1(aZAl8) {eval(\"/*@cc_on var aRg5 = new Date() @*/\");aRg5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRg5[\"getUTC" ascii
    $s2  = "function aFa1(aZAl8) {eval(\"/*@cc_on var aRg5 = new Date() @*/\");aRg5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRg5[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`1`+`1`=`7`b`K`F`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`z`O`a`=`6`a`V`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`q`G`W`a` `r`a`v` ` ` ` \"))," ascii
    $s6  = "s\"]()[\"toString\"](10) == \"20\") {var aVJm5 = aZAl8[\"split\"](\"`\"); return aVJm5[\"reverse\"]().join(\"\");} else return " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`v`V`O`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\"}`;`h`t`a`P`t`r`o`h`S`.`3`k`Z`a` `n`r`u`t`e`r`;`)`6`a`V`a`(`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\"/`*`@` `}`;`8`l`A`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\"/`*`@` `}`;`8`l`A`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\"/`*`@` `}`;`5`m`J`V`a` `n`r`u`t`e`r`;`}`;`)`3`f`E`H`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`1`+`1`=`7`b`K`F`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFa1(\"\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}