rule sig_20161215_dafd44bebb456f18ec7ad776b2f58fa8 {
  meta:
    description = "datamaliciousorder - file 20161215_dafd44bebb456f18ec7ad776b2f58fa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e6b46c386f52d8ca1a81fdd7debae20c6e1f9cbc90cb84d91204b9ffacff48b"

  strings:
    $s1  = "function aIOw6(aWh8) {eval(\"/*@cc_on var aYb9 = new Date() @*/\");aYb9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYb9[\"getUTC" ascii
    $s2  = "function aIOw6(aWh8) {eval(\"/*@cc_on var aYb9 = new Date() @*/\");aYb9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYb9[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "s\"]()[\"toString\"](10) == \"20\") {var aCz9 = aWh8[\"split\"](\"`\"); return aCz9[\"reverse\"]().join(\"\");} else return \"\"" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\"/`*`@` `}`;`)`1`i`V`a`(`0`z`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`p`R`a`=`3`s`U" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\"}`;`h`t`a`P`t`r`o`h`S`.`0`r`L`G`a` `n`r`u`t`e`r`;`)`3`s`U`S" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`0` `=` `5`a`M`D`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`w`L`G`a` `r`a`v` ` ` ` \"))" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`)`\\x22`j`v`n`x`u`/`p`j`.`9`1`1`a`m`a`\\x22` `+` `8`f`E`D" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`1`+`1`=`0`d`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\";`)`\\x22`3`2`i`t`s`/`m`o`c`.`s`b`e`w`0`5`.`e`c`i`v`d`a`l`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIOw6(\"/`*`@` `}`;`)`1`i`V`a`(`0`z`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}