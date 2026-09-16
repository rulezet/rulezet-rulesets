rule sig_20161215_9fcb348cbe8c35545873058cf47589db {
  meta:
    description = "datamaliciousorder - file 20161215_9fcb348cbe8c35545873058cf47589db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68246b2f8bd8477543a9bc391fb2381bc555ea3ca388fbf26b4073f640dd9654"

  strings:
    $s1  = "function aHIq6(aBFf9) {eval(\"/*@cc_on var aWEw0 = new Date() @*/\");aWEw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWEw0[\"ge" ascii
    $s2  = "function aHIq6(aBFf9) {eval(\"/*@cc_on var aWEw0 = new Date() @*/\");aWEw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWEw0[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `4`y" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `4`y`M`P" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`1`+`1`=`3`g`H`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`q`O`Z`a`;`)`2` `,`1`w`A`a`(`]" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`t`W`T`a`=`6`j" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\"/`*`@` `}`;`1`d`I`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`2`j`U`a` `+` `2`r`Z`J`a`=`0`t`W`T`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`d`O`F`a` `r`a`v` `;" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\"/`*`@` `}`;`9`f`F`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`d`O`F`a` `r`a`v` `;" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIq6(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `4`y`M`P" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}