rule sig_20161215_f7434605852f2762facd2ff2374fbf3c {
  meta:
    description = "datamaliciousorder - file 20161215_f7434605852f2762facd2ff2374fbf3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "521cad95b86dae96649c4d30101155c04549ba2e1257014d927bd9d79b43e138"

  strings:
    $s1  = "function aCLn9(aNd5) {eval(\"/*@cc_on var aWHs8 = new Date() @*/\");aWHs8[\"setUTCSeconds\"](\"0\", \"20\");if (aWHs8.getUTCMill" ascii
    $s2  = "function aCLn9(aNd5) {eval(\"/*@cc_on var aWHs8 = new Date() @*/\");aWHs8[\"setUTCSeconds\"](\"0\", \"20\");if (aWHs8.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\"/`*`@` `}`;`5`d`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\"/`*`@` `}`;`)`5`z`H`a`(`3`b`E`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\"}`;`h`t`a`P`t`r`o`h`S`.`1`y`U`a` `n`r`u`t`e`r`;`)`7`u`W`J`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s12 = "().toString(10) == \"20\") {var aZw5 = aNd5[\"split\"](\"`\"); return aZw5.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\"/`*`@` `}`;`)`5`z`H`a`(`3`b`E`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`g`W`a`=`7`u`W" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\";`3`z`T`a` `+` `0`q`H`M`a`=`7`g`W`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\"/`*`@` `}`;`2`o`G`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCLn9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`k`P`N`a`;`)`2` `,`6`j`U`K`a`(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}