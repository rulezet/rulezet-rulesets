rule sig_20161215_3c1de0adc1143b4955e02f0f93231554 {
  meta:
    description = "datamaliciousorder - file 20161215_3c1de0adc1143b4955e02f0f93231554.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "275bb762c713a6d4a194fbddc6f2cdf3e88a18bdfa501109ec9f269466192085"

  strings:
    $s1  = "function aKUi8(aCZv2) {eval(\"/*@cc_on var aFs2 = new Date() @*/\");aFs2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFs2[\"getUT" ascii
    $s2  = "function aKUi8(aCZv2) {eval(\"/*@cc_on var aFs2 = new Date() @*/\");aFs2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFs2[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`1`+`1`=`8`c`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\"/`*`@` `}`;`2`v`Z`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`x`I`Z`a`=`8`t" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`u`U`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`u`U`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`e`C`I`a`(" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `3`j`M`a` `r`a`v` ` ` ` \")), " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\"/`*`@` `}`;`6`e`H`a` `n`r`u`t`e`r`;`}`;`)`8`x`Z`X`a`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKUi8(\"/`*`@` `}`;`5`g`A`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}