rule sig_20161215_56e26e48465a593e4d0c8977e97c2d5c {
  meta:
    description = "datamaliciousorder - file 20161215_56e26e48465a593e4d0c8977e97c2d5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48c7dd9bd4e1a33a56eb1e0ce0cd8d767133efb8f6328013ff72b47d4c56f0c6"

  strings:
    $s1  = "function aFe6(aGBa5) {eval(\"/*@cc_on var aZJt0 = new Date() @*/\");aZJt0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZJt0[\"get" ascii
    $s2  = "function aFe6(aGBa5) {eval(\"/*@cc_on var aZJt0 = new Date() @*/\");aZJt0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZJt0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\"/`*`@` `}`;`4`r`R`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`t`C`a` `r`a`v` `;`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\"/`*`@` `}`;`)`8`l`T`W`a`(`8`r`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\"/`*`@` `}`;`5`a`B`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`)`\\x22`1`t`j`m`g`a`3`/`m`o`c`.`b`l`-`e`c`i`f`f`o`r`e`t`n`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`g`R`a`=`2`h`M`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`1`+`1`=`9`p`L`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\"}`;`h`t`a`P`t`r`o`h`S`.`2`g`D`a` `n`r`u`t`e`r`;`)`2`h`M`R`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFe6(\"/`*`@` `}`;`6`r`T`O`a` `n`r`u`t`e`r`;`}`;`)`0`a`E`B`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}