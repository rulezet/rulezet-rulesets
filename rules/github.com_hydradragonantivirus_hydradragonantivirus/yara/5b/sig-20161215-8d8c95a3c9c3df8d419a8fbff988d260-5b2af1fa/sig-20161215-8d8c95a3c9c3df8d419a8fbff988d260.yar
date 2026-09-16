rule sig_20161215_8d8c95a3c9c3df8d419a8fbff988d260 {
  meta:
    description = "datamaliciousorder - file 20161215_8d8c95a3c9c3df8d419a8fbff988d260.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4def839ed34a10620140d1ab7e66e45424a58f82729e5637629140b0c46a831b"

  strings:
    $s1  = "function aKSu0(aRy9) {eval(\"/*@cc_on var aLUz9 = new Date() @*/\");aLUz9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLUz9[\"get" ascii
    $s2  = "function aKSu0(aRy9) {eval(\"/*@cc_on var aLUz9 = new Date() @*/\");aLUz9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLUz9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`a`Z`a`=`9`n`Z" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `7`d" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`a`Z`a`=`9`n`Z" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\"/`*`@` `}`;`2`p`M`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\"/`*`@` `}`;`2`p`M`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`f`W`Z`a` `r`a`v` `;" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\"/`*`@` `}`;`4`q`B`a` `n`r`u`t`e`r`;`}`;`)`1`d`G`a`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\"/`*`@` `}`;`)`4`n`C`K`a`(`4`q`C`V`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\"/`*`@` `}`;`9`y`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKSu0(\"/`*`@` `}`;`9`y`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}