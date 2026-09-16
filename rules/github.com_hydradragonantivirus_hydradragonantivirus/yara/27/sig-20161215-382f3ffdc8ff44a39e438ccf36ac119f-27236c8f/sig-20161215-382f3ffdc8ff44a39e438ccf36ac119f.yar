rule sig_20161215_382f3ffdc8ff44a39e438ccf36ac119f {
  meta:
    description = "datamaliciousorder - file 20161215_382f3ffdc8ff44a39e438ccf36ac119f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbd1280a29a2cad4ced9996e912309e5adeb1d31141e7021a9e173ef58532d7a"

  strings:
    $s1  = "function aMBs3(aCf6) {eval(\"/*@cc_on var aQRi3 = new Date() @*/\");aQRi3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQRi3[\"get" ascii
    $s2  = "function aMBs3(aCf6) {eval(\"/*@cc_on var aQRi3 = new Date() @*/\");aQRi3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQRi3[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`r`M`N`a`=`3`d" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\"/`*`@` `}`;`)`1`k`E`U`a`(`0`i`R`W`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\"/`*`@` `}`;`5`d`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`w" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`u`S`C`a`;`)`2` `,`4`p`Z`a`(`]" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\"/`*`@` `}`;`)`1`k`E`U`a`(`0`i`R`W`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\"/`*`@` `}`;`3`i`B`a` `n`r`u`t`e`r`;`}`;`)`6`y`H`a`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\"}`;`h`t`a`P`t`r`o`h`S`.`1`z`X`W`a` `n`r`u`t`e`r`;`)`3`d`Y`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\"/`*`@` `}`;`6`f`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `1" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`c`W`S`a` `r`a`v` ` ` ` \"))" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMBs3(\";`0` `=` `8`o`H`Z`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}