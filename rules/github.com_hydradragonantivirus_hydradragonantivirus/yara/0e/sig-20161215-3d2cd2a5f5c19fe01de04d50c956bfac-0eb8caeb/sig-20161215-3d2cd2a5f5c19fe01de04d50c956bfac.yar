rule sig_20161215_3d2cd2a5f5c19fe01de04d50c956bfac {
  meta:
    description = "datamaliciousorder - file 20161215_3d2cd2a5f5c19fe01de04d50c956bfac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb4792fd49eb5380390832c48d6d8c708e3f1f12d2be9e559bbd7b2d4d226aed"

  strings:
    $s1  = "function aZg5(aGXr4) {eval(\"/*@cc_on var aJLs8 = new Date() @*/\");aJLs8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJLs8[\"get" ascii
    $s2  = "function aZg5(aGXr4) {eval(\"/*@cc_on var aJLs8 = new Date() @*/\");aJLs8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJLs8[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\"/`*`@` `}`;`2`a`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`r`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\"/`*`@` `}`;`4`p`P`a` `n`r`u`t`e`r`;`}`;`)`9`g`C`a`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`v`I`a`=`4`p`V`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`t`I`F`a` `n`r`u`t`e`r`;`)`4`p`V`B`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`0` `=` `0`e`F`Q`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`g`R`Z`a`;`)`2` `,`0`d`R`Y`a`(`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`t`I`F`a` `n`r`u`t`e`r`;`)`4`p`V`B`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\"/`*`@` `}`;`)`9`v`Q`X`a`(`9`m`R`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`e`U`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\"/`*`@` `}`;`4`r`X`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\";`1`+`1`=`1`n`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZg5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}