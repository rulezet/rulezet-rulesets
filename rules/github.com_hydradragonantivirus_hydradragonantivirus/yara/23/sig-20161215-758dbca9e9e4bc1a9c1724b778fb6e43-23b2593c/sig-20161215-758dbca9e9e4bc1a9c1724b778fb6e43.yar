rule sig_20161215_758dbca9e9e4bc1a9c1724b778fb6e43 {
  meta:
    description = "datamaliciousorder - file 20161215_758dbca9e9e4bc1a9c1724b778fb6e43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cee8a16df782a38a292df3823b055439f5236a49c520358e3f69f0ec11bda1d"

  strings:
    $s1  = "function aHh0(aOf5) {eval(\"/*@cc_on var aKl0 = new Date() @*/\");aKl0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKl0[\"getUTCM" ascii
    $s2  = "function aHh0(aOf5) {eval(\"/*@cc_on var aKl0 = new Date() @*/\");aKl0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKl0[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\"}`;`h`t`a`P`t`r`o`h`S`.`6`j`U`a` `n`r`u`t`e`r`;`)`8`s`I`M`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`)`\\x22`g`v`j`j`y`/`m`o`c`.`c`e`l`e`s`e`k`y`d`\\x22` `+` `" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\"/`*`@` `}`;`3`h`O`Q`a` `n`r`u`t`e`r`;`}`;`)`1`o`Y`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\"/`*`@` `}`;`5`f`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`0` `=` `4`s`A`H`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`k`F`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\"/`*`@` `}`;`)`1`b`Q`a`(`5`d`F`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`l`U`a`;`)`2` `,`7`i`C`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\"/`*`@` `}`;`)`1`b`Q`a`(`5`d`F`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHh0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}