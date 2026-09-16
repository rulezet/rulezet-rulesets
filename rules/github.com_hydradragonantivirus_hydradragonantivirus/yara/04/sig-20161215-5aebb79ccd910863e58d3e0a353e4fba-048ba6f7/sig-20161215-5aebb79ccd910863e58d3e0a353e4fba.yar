rule sig_20161215_5aebb79ccd910863e58d3e0a353e4fba {
  meta:
    description = "datamaliciousorder - file 20161215_5aebb79ccd910863e58d3e0a353e4fba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d410ba22dbf1faf119f2b1d8b977fbe7fad7cf5f4566c76ec14dd33941a6e44"

  strings:
    $s1  = "function aYBa6(aGp3) {eval(\"/*@cc_on var aMVv7 = new Date() @*/\");aMVv7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMVv7[\"get" ascii
    $s2  = "function aYBa6(aGp3) {eval(\"/*@cc_on var aMVv7 = new Date() @*/\");aMVv7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMVv7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\"/`*`@` `}`;`3`b`G`G`a` `n`r`u`t`e`r`;`}`;`)`1`f`U`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`1`+`1`=`8`f`P`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\"/`*`@` `}`;`8`l`P`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\"/`*`@` `}`;`3`p`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\"}`;`h`t`a`P`t`r`o`h`S`.`4`f`Q`M`a` `n`r`u`t`e`r`;`)`8`a`C`J" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`o`C`a`=`8`a`C" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\"/`*`@` `}`;`3`p`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`)`\\x22`h`k`m`s`y`2`4`b`t`f`/`t`e`n`.`u`t`n`a`u`h`c`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\"/`*`@` `}`;`)`8`i`G`a`(`9`f`I`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`1`+`1`=`8`f`P`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`y`N`a`;`)`2` `,`8`m`F`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\"/`*`@` `}`;`)`8`i`G`a`(`9`f`I`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYBa6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}