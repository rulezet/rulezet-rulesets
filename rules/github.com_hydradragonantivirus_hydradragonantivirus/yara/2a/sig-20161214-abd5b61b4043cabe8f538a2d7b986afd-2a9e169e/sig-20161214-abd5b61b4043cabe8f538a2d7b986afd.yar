rule sig_20161214_abd5b61b4043cabe8f538a2d7b986afd {
  meta:
    description = "datamaliciousorder - file 20161214_abd5b61b4043cabe8f538a2d7b986afd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57e00fc1ab45360db418e77d3cc1e47bbb2ce70090e3a4bd85592bc75675a552"

  strings:
    $s1  = "function aJh3(aYBy7) {eval(\"/*@cc_on var aBv1 = new Date() @*/\");aBv1[\"setUTCSeconds\"](\"0\", \"20\");if (aBv1.getUTCMillise" ascii
    $s2  = "function aJh3(aYBy7) {eval(\"/*@cc_on var aBv1 = new Date() @*/\");aBv1[\"setUTCSeconds\"](\"0\", \"20\");if (aBv1.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\"/`*`@` `}`;`7`y`B`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`s`A`a`=`0`r`N`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`8`w`X`F`a` `+` `4`s`B`V`a`=`6`s`A`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`1`+`1`=`5`g`I`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`m`K`a`;`)`2` `,`4`r`C`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\"/`*`@` `}`;`)`7`o`T`L`a`(`4`s`B`H`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\"/`*`@` `}`;`8`n`G`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`i`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `6`p`T`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJh3(\"/`*`@` `}`;`7`y`B`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}