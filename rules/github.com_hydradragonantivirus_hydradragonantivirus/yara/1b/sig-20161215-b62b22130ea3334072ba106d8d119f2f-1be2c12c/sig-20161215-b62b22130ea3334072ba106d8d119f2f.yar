rule sig_20161215_b62b22130ea3334072ba106d8d119f2f {
  meta:
    description = "datamaliciousorder - file 20161215_b62b22130ea3334072ba106d8d119f2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ae627f7b8ccb3ecb649253461c1b46ebe4dece29556534bb1e9b4a8077234e8"

  strings:
    $s1  = "function aEd5(aPEj6) {eval(\"/*@cc_on var aCEb0 = new Date() @*/\");aCEb0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCEb0[\"get" ascii
    $s2  = "function aEd5(aPEj6) {eval(\"/*@cc_on var aCEb0 = new Date() @*/\");aCEb0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCEb0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\"/`*`@` `}`;`)`0`k`R`a`(`4`x`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`1`+`1`=`2`e`R`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`0` `=` `3`h`R`U`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `7`r`" ascii
    $s9  = "onds\"]()[\"toString\"](10) == \"20\") {var aGj0 = aPEj6[\"split\"](\"`\"); return aGj0[\"reverse\"]().join(\"\");} else return " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`1`+`1`=`2`e`R`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`g`M`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\"/`*`@` `}`;`6`j`E`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\"/`*`@` `}`;`6`j`E`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\"/`*`@` `}`;`0`r`G`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\"/`*`@` `}`;`0`j`G`a` `n`r`u`t`e`r`;`}`;`)`1`v`D`a`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`y`I`a`=`0`s`T`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEd5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}