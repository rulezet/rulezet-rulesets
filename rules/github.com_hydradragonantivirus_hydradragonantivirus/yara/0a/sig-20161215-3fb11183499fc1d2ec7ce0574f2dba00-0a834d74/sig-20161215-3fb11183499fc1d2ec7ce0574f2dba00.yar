rule sig_20161215_3fb11183499fc1d2ec7ce0574f2dba00 {
  meta:
    description = "datamaliciousorder - file 20161215_3fb11183499fc1d2ec7ce0574f2dba00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea3ffd4528979aabd02ff5959f4034597e93ba5806ed6a5748a54aecc7ebd877"

  strings:
    $s1  = "function aAOh2(aOy3) {eval(\"/*@cc_on var aVk9 = new Date() @*/\");aVk9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVk9[\"getUTC" ascii
    $s2  = "function aAOh2(aOy3) {eval(\"/*@cc_on var aVk9 = new Date() @*/\");aVk9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVk9[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\"/`*`@` `}`;`7`h`M`Z`a` `n`r`u`t`e`r`;`}`;`)`3`n`O`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `1`j`M`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\"/`*`@` `}`;`)`8`w`X`M`a`(`9`p`M`H`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\"/`*`@` `}`;`3`y`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "s\"]()[\"toString\"](10) == \"20\") {var aZMh7 = aOy3[\"split\"](\"`\"); return aZMh7[\"reverse\"]().join(\"\");} else return \"" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\"/`*`@` `}`;`4`f`E`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`s`E`a`;`)`2` `,`9`j`H`F`a`(`]" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `1`j`M`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`s`N`P`a` `r`a`v` `;" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`r`X`F`a`=`8`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAOh2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}