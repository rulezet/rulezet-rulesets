rule sig_20161215_6f7e11f2ece730e4be8834a342e34ae8 {
  meta:
    description = "datamaliciousorder - file 20161215_6f7e11f2ece730e4be8834a342e34ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ace1a0bec288a7f7edf3951db3357e9782bd7ff8e88d8edfedb59752977eca92"

  strings:
    $s1  = "function aYVr4(aGo0) {eval(\"/*@cc_on var aNo9 = new Date() @*/\");aNo9[\"setUTCSeconds\"](\"0\", \"20\");if (aNo9.getUTCMillise" ascii
    $s2  = "function aYVr4(aGo0) {eval(\"/*@cc_on var aNo9 = new Date() @*/\");aNo9[\"setUTCSeconds\"](\"0\", \"20\");if (aNo9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`j`S`a` `n`r`u`t`e`r`;`)`2`a`D`a`(" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`w`U`G`a`=`2`a" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`f`C`W`a`;`)`2` `,`4`a`Z`N`a`(" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`0` `=` `3`x`K`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`j`S`a` `n`r`u`t`e`r`;`)`2`a`D`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`1`+`1`=`0`k`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\"/`*`@` `}`;`0`o`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\"/`*`@` `}`;`1`y`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`y" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYVr4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}