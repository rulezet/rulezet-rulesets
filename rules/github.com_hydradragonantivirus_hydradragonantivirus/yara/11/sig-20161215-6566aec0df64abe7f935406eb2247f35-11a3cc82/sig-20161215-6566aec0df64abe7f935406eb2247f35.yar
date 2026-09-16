rule sig_20161215_6566aec0df64abe7f935406eb2247f35 {
  meta:
    description = "datamaliciousorder - file 20161215_6566aec0df64abe7f935406eb2247f35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4c5217b07785b505e227b2ab3996734e9bf8f0d1095773f6f2f19d79eade237"

  strings:
    $s1  = "function aJu9(aHAi1) {eval(\"/*@cc_on var aWVj7 = new Date() @*/\");aWVj7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWVj7[\"get" ascii
    $s2  = "function aJu9(aHAi1) {eval(\"/*@cc_on var aWVj7 = new Date() @*/\");aWVj7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWVj7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`x`M`a`;`)`2` `,`6`k`J`G`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"}`;`h`t`a`P`t`r`o`h`S`.`8`b`V`a` `n`r`u`t`e`r`;`)`3`u`K`a`(`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` `" ascii
    $s6  = "onds\"]()[\"toString\"](10) == \"20\") {var aQc7 = aHAi1[\"split\"](\"`\"); return aQc7[\"reverse\"]().join(\"\");} else return " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"/`*`@` `}`;`7`c`Q`a` `n`r`u`t`e`r`;`}`;`)`8`w`J`a`(`]`\\x22`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\";`0` `=` `1`x`K`Z`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`g`B`F`a` `r`a`v` ` ` ` \"))," ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\";`)`\\x22`v`w`h`2`8`/`m`o`c`.`g`f`s`u`m`a`n`i`d`\\x22` `+` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"/`*`@` `}`;`1`k`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`s`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"/`*`@` `}`;`)`8`m`Y`a`(`2`m`S`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\";`2`z`A`a` `+` `9`k`D`a`=`2`k`M`H`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"}`;`h`t`a`P`t`r`o`h`S`.`8`b`V`a` `n`r`u`t`e`r`;`)`3`u`K`a`(`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"/`*`@` `}`;`7`c`Q`a` `n`r`u`t`e`r`;`}`;`)`8`w`J`a`(`]`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJu9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}