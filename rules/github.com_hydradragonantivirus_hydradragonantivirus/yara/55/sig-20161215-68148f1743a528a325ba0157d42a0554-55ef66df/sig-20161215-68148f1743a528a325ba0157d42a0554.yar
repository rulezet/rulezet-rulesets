rule sig_20161215_68148f1743a528a325ba0157d42a0554 {
  meta:
    description = "datamaliciousorder - file 20161215_68148f1743a528a325ba0157d42a0554.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35f735695cdaea704613e31c80e48800b6b8184fac7687fe945eac7d9a56cbd5"

  strings:
    $s1  = "function aTJq9(aVVu2) {eval(\"/*@cc_on var aLi1 = new Date() @*/\");aLi1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLi1[\"getUT" ascii
    $s2  = "function aTJq9(aVVu2) {eval(\"/*@cc_on var aLi1 = new Date() @*/\");aLi1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLi1[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`1`+`1`=`4`v`X`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`c`K`L`a` `r`a`v` `;" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`)`\\x22`1`p`a`y`d`/`s`e`.`r`a`c`i`f`a`\\x22` `+` `8`z`G`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\"/`*`@` `}`;`2`u`V`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`i`I`a`=`6`g`F" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`0` `=` `7`h`Y`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\"/`*`@` `}`;`9`b`T`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`i`I`a`=`6`g`F" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTJq9(\";`1`+`1`=`4`v`X`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}