rule sig_20161215_4c87ab2fe2487448e311028f792ccb88 {
  meta:
    description = "datamaliciousorder - file 20161215_4c87ab2fe2487448e311028f792ccb88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b81dcb2a545a9860114d1b2e378c6fc7bb1009f67c0e7f2a91e999399499e27"

  strings:
    $s1  = "function aXXz9(aJSg6) {eval(\"/*@cc_on var aUz1 = new Date() @*/\");aUz1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUz1[\"getUT" ascii
    $s2  = "function aXXz9(aJSg6) {eval(\"/*@cc_on var aUz1 = new Date() @*/\");aUz1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUz1[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`r`Y`T`a` `r`a`v` `;" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`i`K`P`a`=`7`y" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`i`K`P`a`=`7`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\"}`;`h`t`a`P`t`r`o`h`S`.`5`z`S`N`a` `n`r`u`t`e`r`;`)`7`y`N`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\"/`*`@` `}`;`)`2`w`I`a`(`3`c`L`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`e`I`a`;`)`2` `,`9`u`I`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\"/`*`@` `}`;`6`g`S`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`0` `=` `9`c`F`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`r`Y`T`a` `r`a`v` `;" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXXz9(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}