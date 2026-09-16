rule sig_20161215_45e525754d40dfe25f632e19660fd036 {
  meta:
    description = "datamaliciousorder - file 20161215_45e525754d40dfe25f632e19660fd036.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e6432daea8403dd8f4671982df89723aa9143a3169f2ebdecbd6a6895fab02b"

  strings:
    $s1  = "function aFb3(aREn7) {eval(\"/*@cc_on var aTHy7 = new Date() @*/\");aTHy7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTHy7[\"get" ascii
    $s2  = "function aFb3(aREn7) {eval(\"/*@cc_on var aTHy7 = new Date() @*/\");aTHy7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTHy7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`6`c`K`T`a` `+` `4`s`H`G`a`=`5`g`X`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\"/`*`@` `}`;`)`3`q`D`P`a`(`1`b`W`N`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`m`f`a`6`0`v`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`t`n`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\"/`*`@` `}`;`)`3`q`D`P`a`(`1`b`W`N`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`m`f`a`6`0`v`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`t`n`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`3`b`m`e`f`1`n`x`w`v`/`m`o`c`.`o`b`a`l`-`s`w`e`m`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`p`Z`I`a`;`)`2` `,`9`e`B`V`a`(`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\"\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`g`X`a`=`1`q`K`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`g`K`L`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\"/`*`@` `}`;`2`t`V`a` `n`r`u`t`e`r`;`}`;`)`9`v`E`M`a`(`]`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFb3(\";`)`\\x22`3`b`m`e`f`1`n`x`w`v`/`m`o`c`.`o`b`a`l`-`s`w`e`m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}