rule sig_20161215_b850c0226356c0c5783adef14ef2970f {
  meta:
    description = "datamaliciousorder - file 20161215_b850c0226356c0c5783adef14ef2970f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7af07b36941b77b0a15921b2b4f83eed813b62c6c57e039e99d66f02f27c0fdd"

  strings:
    $s1  = "function aVj1(aOu1) {eval(\"/*@cc_on var aUf2 = new Date() @*/\");aUf2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUf2[\"getUTCM" ascii
    $s2  = "function aVj1(aOu1) {eval(\"/*@cc_on var aUf2 = new Date() @*/\");aUf2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUf2[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`9`w`G`H`a` `+` `0`d`N`a`=`3`y`X`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`s`O`a`;`)`2` `,`0`x`M`S`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` `" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`m`T`W`a` `r`a`v` `;`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\"/`*`@` `}`;`1`u`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`1`+`1`=`2`k`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\"/`*`@` `}`;`8`j`P`Q`a` `n`r`u`t`e`r`;`}`;`)`3`s`U`O`a`(`]`" ascii
    $s12 = "\"]()[\"toString\"](10) == \"20\") {var aQPj8 = aOu1[\"split\"](\"`\"); return aQPj8[\"reverse\"]().join(\"\");} else return \"" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\"/`*`@` `}`;`0`3`r`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\"/`*`@` `}`;`0`3`r`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVj1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`s`O`a`;`)`2` `,`0`x`M`S`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}