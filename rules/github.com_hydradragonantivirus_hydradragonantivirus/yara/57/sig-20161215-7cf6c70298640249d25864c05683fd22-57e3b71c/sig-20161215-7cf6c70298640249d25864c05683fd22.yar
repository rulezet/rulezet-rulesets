rule sig_20161215_7cf6c70298640249d25864c05683fd22 {
  meta:
    description = "datamaliciousorder - file 20161215_7cf6c70298640249d25864c05683fd22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08940f311dbb43ae718160798f0debcb147ad49beaeebd60e4664d631c407515"

  strings:
    $s1  = "function aNDa6(aPl6) {eval(\"/*@cc_on var aYZk9 = new Date() @*/\");aYZk9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYZk9[\"get" ascii
    $s2  = "function aNDa6(aPl6) {eval(\"/*@cc_on var aYZk9 = new Date() @*/\");aYZk9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYZk9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "onds\"]()[\"toString\"](10) == \"20\") {var aTDb8 = aPl6[\"split\"](\"`\"); return aTDb8[\"reverse\"]().join(\"\");} else return" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\"/`*`@` `}`;`)`9`r`T`a`(`9`c`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\"/`*`@` `}`;`6`l`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\"}`;`h`t`a`P`t`r`o`h`S`.`2`h`X`a` `n`r`u`t`e`r`;`)`7`t`K`a`(" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`q`J`P`a`=`7`t" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`1`+`1`=`9`p`X`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\"/`*`@` `}`;`8`b`D`T`a` `n`r`u`t`e`r`;`}`;`)`0`b`A`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`x`B`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`9`d`J`a` `+` `5`y`Z`M`a`=`6`q`J`P`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`b`S`R`a`;`)`2` `,`2`u`E`M`a`(" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNDa6(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}