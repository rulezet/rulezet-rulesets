rule sig_20161215_de9e316112afbda095891ba8f13ef6c6 {
  meta:
    description = "datamaliciousorder - file 20161215_de9e316112afbda095891ba8f13ef6c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa81a4ff123b53893f27ef9df38f2da08ff3d26a4bbf2ef335f4ed9d27822178"

  strings:
    $s1  = "function aWv2(aRYa6) {eval(\"/*@cc_on var aQPi0 = new Date() @*/\");aQPi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQPi0[\"get" ascii
    $s2  = "function aWv2(aRYa6) {eval(\"/*@cc_on var aQPi0 = new Date() @*/\");aQPi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQPi0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"}`;`h`t`a`P`t`r`o`h`S`.`7`b`N`a` `n`r`u`t`e`r`;`)`6`u`H`I`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`u`K`Y`a`;`)`2` `,`8`m`T`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"/`*`@` `}`;`6`a`Y`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"/`*`@` `}`;`1`w`S`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"/`*`@` `}`;`0`p`J`a` `n`r`u`t`e`r`;`}`;`)`0`e`O`X`a`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"}`;`h`t`a`P`t`r`o`h`S`.`7`b`N`a` `n`r`u`t`e`r`;`)`6`u`H`I`a`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`)`\\x22`v`w`h`2`8`/`m`o`c`.`g`f`s`u`m`a`n`i`d`\\x22` `+` `" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"/`*`@` `}`;`)`2`t`E`A`a`(`7`q`S`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`t`Z`a` `r`a`v` `;`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`u`K`Y`a`;`)`2` `,`8`m`T`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}