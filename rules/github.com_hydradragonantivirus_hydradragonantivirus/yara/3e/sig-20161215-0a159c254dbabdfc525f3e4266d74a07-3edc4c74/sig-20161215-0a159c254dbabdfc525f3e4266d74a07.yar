rule sig_20161215_0a159c254dbabdfc525f3e4266d74a07 {
  meta:
    description = "datamaliciousorder - file 20161215_0a159c254dbabdfc525f3e4266d74a07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d95a1d5438acdf62f8c88df8a8b7bbb3168604d4f004dd766fd88e5475077719"

  strings:
    $s1  = "function aXYp1(aYOf4) {eval(\"/*@cc_on var aCp8 = new Date() @*/\");aCp8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCp8[\"getUT" ascii
    $s2  = "function aXYp1(aYOf4) {eval(\"/*@cc_on var aCp8 = new Date() @*/\");aCp8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCp8[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"/`*`@` `}`;`4`f`O`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\";`)`\\x22`m`f`a`6`0`v`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`t`n" ascii
    $s5  = "ds\"]()[\"toString\"](10) == \"20\") {var aKUb0 = aYOf4[\"split\"](\"`\"); return aKUb0[\"reverse\"]().join(\"\");} else return " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"/`*`@` `}`;`0`b`U`K`a` `n`r`u`t`e`r`;`}`;`)`6`z`W`a`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"/`*`@` `}`;`)`1`d`T`a`(`9`g`G`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`s`B`a`;`)`2` `,`0`x`M`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\";`0` `=` `7`k`F`F`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\";`)`\\x22`j`v`n`x`u`/`p`j`.`9`1`1`a`m`a`\\x22` `+` `5`y`A`H" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`s`B`a`;`)`2` `,`0`x`M`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`n`V`a` `r`a`v` ` ` ` \")), " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"/`*`@` `}`;`0`g`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`m`V`a`=`9`y`U" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\";`1`+`1`=`4`n`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXYp1(\"/`*`@` `}`;`4`f`O`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}