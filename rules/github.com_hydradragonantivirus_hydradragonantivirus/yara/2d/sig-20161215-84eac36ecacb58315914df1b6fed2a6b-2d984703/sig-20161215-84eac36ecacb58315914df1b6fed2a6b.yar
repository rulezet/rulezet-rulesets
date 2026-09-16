rule sig_20161215_84eac36ecacb58315914df1b6fed2a6b {
  meta:
    description = "datamaliciousorder - file 20161215_84eac36ecacb58315914df1b6fed2a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2515f1df59f485c393469a2d7f361c6a1630b51dfb92926f72e41126214a18c5"

  strings:
    $s1  = "function aOu3(aIGc7) {eval(\"/*@cc_on var aYOs8 = new Date() @*/\");aYOs8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYOs8[\"get" ascii
    $s2  = "function aOu3(aIGc7) {eval(\"/*@cc_on var aYOs8 = new Date() @*/\");aYOs8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYOs8[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`b`H`a`;`)`2` `,`2`b`X`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`0` `=` `2`r`L`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "onds\"]()[\"toString\"](10) == \"20\") {var aIz4 = aIGc7[\"split\"](\"`\"); return aIz4[\"reverse\"]().join(\"\");} else return " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`d`M`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\"/`*`@` `}`;`)`3`r`Y`a`(`1`t`I`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\"/`*`@` `}`;`4`z`I`a` `n`r`u`t`e`r`;`}`;`)`8`d`B`B`a`(`]`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`6`z`A`Y`a` `+` `2`l`H`a`=`3`u`J`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`u`J`a`=`8`b`Z`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\"/`*`@` `}`;`3`b`I`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOu3(\"/`*`@` `}`;`7`c`G`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}