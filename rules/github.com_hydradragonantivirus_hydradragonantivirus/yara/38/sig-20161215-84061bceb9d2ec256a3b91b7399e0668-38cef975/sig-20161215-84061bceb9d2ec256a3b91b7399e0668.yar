rule sig_20161215_84061bceb9d2ec256a3b91b7399e0668 {
  meta:
    description = "datamaliciousorder - file 20161215_84061bceb9d2ec256a3b91b7399e0668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10e7de9ce0a1f00443aa4fc44cf4443fc03d088dcaba02e5b82993063a6ae401"

  strings:
    $s1  = "function aRp7(aOCw2) {eval(\"/*@cc_on var aWDf5 = new Date() @*/\");aWDf5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWDf5[\"get" ascii
    $s2  = "function aRp7(aOCw2) {eval(\"/*@cc_on var aWDf5 = new Date() @*/\");aWDf5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWDf5[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`v`V`I`a`=`6`b`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`s`C`C`a` `r`a`v` ` ` ` \"))," ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\"/`*`@` `}`;`7`g`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`g`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\"/`*`@` `}`;`)`8`k`W`S`a`(`3`l`T`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\"/`*`@` `}`;`)`8`k`W`S`a`(`3`l`T`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\"/`*`@` `}`;`2`m`I`H`a` `n`r`u`t`e`r`;`}`;`)`4`u`R`D`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\"/`*`@` `}`;`7`g`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`g`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`b`E`K`a` `r`a`v` `;`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\"}`;`h`t`a`P`t`r`o`h`S`.`0`j`S`P`a` `n`r`u`t`e`r`;`)`6`b`Z`E`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRp7(\";`0` `=` `2`g`F`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}