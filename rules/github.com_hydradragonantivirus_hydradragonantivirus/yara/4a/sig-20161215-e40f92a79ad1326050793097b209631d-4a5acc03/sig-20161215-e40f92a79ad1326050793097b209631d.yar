rule sig_20161215_e40f92a79ad1326050793097b209631d {
  meta:
    description = "datamaliciousorder - file 20161215_e40f92a79ad1326050793097b209631d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a72512ed4d2fc51de5033da2ebc940d5da16107b8e972a7367599db6112f9013"

  strings:
    $s1  = "function aWp6(aEUc0) {eval(\"/*@cc_on var aGk3 = new Date() @*/\");aGk3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGk3[\"getUTC" ascii
    $s2  = "function aWp6(aEUc0) {eval(\"/*@cc_on var aGk3 = new Date() @*/\");aGk3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGk3[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`j`Z`a` `r`a`v` `;`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\"/`*`@` `}`;`1`w`J`a` `n`r`u`t`e`r`;`}`;`)`3`b`X`a`(`]`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`4`t`V`a` `+` `9`l`K`V`a`=`1`v`B`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`j`Z`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`z`J`S`a` `n`r`u`t`e`r`;`)`2`k`E`J`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`1`+`1`=`9`n`Y`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`1`+`1`=`9`n`Y`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\"/`*`@` `}`;`0`c`U`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`z`J`S`a` `n`r`u`t`e`r`;`)`2`k`E`J`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\"/`*`@` `}`;`0`c`U`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\"/`*`@` `}`;`1`u`G`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWp6(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}