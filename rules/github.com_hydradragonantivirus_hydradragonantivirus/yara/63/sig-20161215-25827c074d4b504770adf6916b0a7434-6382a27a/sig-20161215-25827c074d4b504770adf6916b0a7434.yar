rule sig_20161215_25827c074d4b504770adf6916b0a7434 {
  meta:
    description = "datamaliciousorder - file 20161215_25827c074d4b504770adf6916b0a7434.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f114680aa22aaeddf4737c58e2bc29a5206716f357aad377cbbfc03dbb866f5e"

  strings:
    $s1  = "function aBOf0(aIVm3) {eval(\"/*@cc_on var aHWe3 = new Date() @*/\");aHWe3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHWe3[\"ge" ascii
    $s2  = "function aBOf0(aIVm3) {eval(\"/*@cc_on var aHWe3 = new Date() @*/\");aHWe3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHWe3[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`o`L`K`a`;`)`2` `,`0`k`L`Z`a`(" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\"}`;`h`t`a`P`t`r`o`h`S`.`8`y`G`a` `n`r`u`t`e`r`;`)`0`i`E`Q`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\"/`*`@` `}`;`)`8`y`M`a`(`3`v`X`V`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\"/`*`@` `}`;`3`m`V`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\"}`;`h`t`a`P`t`r`o`h`S`.`8`y`G`a` `n`r`u`t`e`r`;`)`0`i`E`Q`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\"/`*`@` `}`;`7`i`Y`Z`a` `n`r`u`t`e`r`;`}`;`)`9`g`C`O`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`\\x22`a`i`v`p`e`c`0`/`e`d`.`a`v`i`d`-`s`l`e`g`n`a`-`n`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`y`I`a` `r`a`v` `;`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBOf0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`y`I`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}