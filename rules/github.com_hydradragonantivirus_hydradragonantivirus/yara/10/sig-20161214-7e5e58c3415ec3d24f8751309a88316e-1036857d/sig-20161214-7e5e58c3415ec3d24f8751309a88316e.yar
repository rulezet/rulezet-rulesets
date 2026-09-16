rule sig_20161214_7e5e58c3415ec3d24f8751309a88316e {
  meta:
    description = "datamaliciousorder - file 20161214_7e5e58c3415ec3d24f8751309a88316e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46399a4dd4d94958a96c0a6ee95235b42cdec56608e6775728c219a3279c232b"

  strings:
    $s1  = "function aNt6(aId3) {eval(\"/*@cc_on var aOm7 = new Date() @*/\");aOm7[\"setUTCSeconds\"](\"0\", \"20\");if (aOm7.getUTCMillisec" ascii
    $s2  = "function aNt6(aId3) {eval(\"/*@cc_on var aOm7 = new Date() @*/\");aOm7[\"setUTCSeconds\"](\"0\", \"20\");if (aOm7.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\"/`*`@` `}`;`7`t`T`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`1`+`1`=`2`f`M`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\"/`*`@` `}`;`8`o`Z`M`a` `n`r`u`t`e`r`;`}`;`)`8`a`Y`N`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\"/`*`@` `}`;`8`o`Z`M`a` `n`r`u`t`e`r`;`}`;`)`8`a`Y`N`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`3`j`Z`R`a` `+` `0`x`A`V`a`=`6`h`O`D`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\"}`;`h`t`a`P`t`r`o`h`S`.`4`h`T`a` `n`r`u`t`e`r`;`)`1`q`T`a`(`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`h`O`D`a`=`1`q`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt6(\"/`*`@` `}`;`3`d`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}