rule sig_20161215_aae1889f548277732ff04910685b70f9 {
  meta:
    description = "datamaliciousorder - file 20161215_aae1889f548277732ff04910685b70f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb5298f329899dfaf20db033802b18b70d991b1749fe6bc8ec3ef2095a94d0cb"

  strings:
    $s1  = "function aWQj9(aMv5) {eval(\"/*@cc_on var aANf9 = new Date() @*/\");aANf9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aANf9[\"get" ascii
    $s2  = "function aWQj9(aMv5) {eval(\"/*@cc_on var aANf9 = new Date() @*/\");aANf9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aANf9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `9`x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`1`+`1`=`7`k`P`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\"}`;`h`t`a`P`t`r`o`h`S`.`5`k`O`a` `n`r`u`t`e`r`;`)`1`d`Q`V`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\"/`*`@` `}`;`7`p`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`p" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`b`D`A`a`;`)`2` `,`7`y`I`a`(`]" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`s`R`G`a` `r`a`v` ` ` ` \"))" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\"/`*`@` `}`;`7`p`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`p" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`p`G`a`=`1`d`Q" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\"/`*`@` `}`;`0`k`B`I`a` `n`r`u`t`e`r`;`}`;`)`7`u`Y`a`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWQj9(\"/`*`@` `}`;`)`7`h`Z`a`(`6`x`R`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}