rule sig_20161215_9d82a8569baec4e214ff09cb2e0f7d12 {
  meta:
    description = "datamaliciousorder - file 20161215_9d82a8569baec4e214ff09cb2e0f7d12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e1108ede8af9a1ca63f62a39be5d9bfd8e0af53bebf7a2646718703f907d357"

  strings:
    $s1  = "function aZi5(aAc7) {eval(\"/*@cc_on var aBn1 = new Date() @*/\");aBn1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBn1[\"getUTCM" ascii
    $s2  = "function aZi5(aAc7) {eval(\"/*@cc_on var aBn1 = new Date() @*/\");aBn1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBn1[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`h`M`a` `n`r`u`t`e`r`;`)`8`l`W`a`(`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"/`*`@` `}`;`7`c`A`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`h`M`a` `n`r`u`t`e`r`;`)`8`l`W`a`(`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\";`2`c`I`O`a` `+` `6`x`J`a`=`9`j`E`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"/`*`@` `}`;`0`v`X`a` `n`r`u`t`e`r`;`}`;`)`0`6`x`J`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"/`*`@` `}`;`0`v`X`a` `n`r`u`t`e`r`;`}`;`)`0`6`x`J`a`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`n`U`a`;`)`2` `,`3`h`O`I`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"/`*`@` `}`;`7`c`A`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\"/`*`@` `}`;`)`5`z`B`a`(`0`n`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `7`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZi5(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}