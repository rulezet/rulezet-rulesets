rule sig_20161215_fb755f2245e7636d75f1ad2152aaea88 {
  meta:
    description = "datamaliciousorder - file 20161215_fb755f2245e7636d75f1ad2152aaea88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a118d82a914e00357a84a0ce095a6aecbdaf09458ca8056d09f5218b4c2568d"

  strings:
    $s1  = "function aBIm6(aYm4) {eval(\"/*@cc_on var aUd9 = new Date() @*/\");aUd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUd9[\"getUTC" ascii
    $s2  = "function aBIm6(aYm4) {eval(\"/*@cc_on var aUd9 = new Date() @*/\");aUd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUd9[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\"}`;`h`t`a`P`t`r`o`h`S`.`8`g`V`S`a` `n`r`u`t`e`r`;`)`0`w`Q`a" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`t`J`a`=`0`w`Q" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\"/`*`@` `}`;`)`6`v`R`a`(`9`q`L`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`j`T`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `2`f" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`i`G`N`a`;`)`2` `,`6`t`N`S`a`(" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\"/`*`@` `}`;`7`h`B`a` `n`r`u`t`e`r`;`}`;`)`6`t`K`a`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\"/`*`@` `}`;`6`c`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`m" ascii
    $s16 = "s\"]()[\"toString\"](10) == \"20\") {var aBh7 = aYm4[\"split\"](\"`\"); return aBh7[\"reverse\"]().join(\"\");} else return \"\"" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`t`J`a`=`0`w`Q" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`1`+`1`=`8`j`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBIm6(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `2`f`T`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}