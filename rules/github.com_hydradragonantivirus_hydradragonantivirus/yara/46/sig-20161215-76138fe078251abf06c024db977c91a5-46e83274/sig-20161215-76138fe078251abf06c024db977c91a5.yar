rule sig_20161215_76138fe078251abf06c024db977c91a5 {
  meta:
    description = "datamaliciousorder - file 20161215_76138fe078251abf06c024db977c91a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49e11930db5eaccec0a225167590d2ad1b8b29d5b168daa907f4e3f5965a82f6"

  strings:
    $s1  = "function aXZt9(aGYd6) {eval(\"/*@cc_on var aQSs9 = new Date() @*/\");aQSs9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQSs9[\"ge" ascii
    $s2  = "function aXZt9(aGYd6) {eval(\"/*@cc_on var aQSs9 = new Date() @*/\");aQSs9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQSs9[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\"/`*`@` `}`;`)`5`k`G`a`(`9`p`Y`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`r`P`L`a`;`)`2` `,`2`l`F`L`a`(" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\"/`*`@` `}`;`0`t`Q`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\"/`*`@` `}`;`8`a`I`T`a` `n`r`u`t`e`r`;`}`;`)`6`b`N`N`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`i`X`a` `r`a`v` ` ` ` \")), " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\"\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "conds\"]()[\"toString\"](10) == \"20\") {var aTIa8 = aGYd6[\"split\"](\"`\"); return aTIa8[\"reverse\"]().join(\"\");} else retu" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\"}`;`h`t`a`P`t`r`o`h`S`.`0`b`B`a` `n`r`u`t`e`r`;`)`8`h`A`I`a" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `6`c`Q`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXZt9(\";`0` `=` `3`u`D`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}