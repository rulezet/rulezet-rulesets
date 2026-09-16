rule sig_20161215_a1854228fd81409f44b28f459d5bf38b {
  meta:
    description = "datamaliciousorder - file 20161215_a1854228fd81409f44b28f459d5bf38b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6dd3138d6cca2c12dd0b32ab83d1a8f0be2dd911963c25c71d641bc06f460a34"

  strings:
    $s1  = "function aYv6(aEn4) {eval(\"/*@cc_on var aLZp5 = new Date() @*/\");aLZp5[\"setUTCSeconds\"](\"0\", \"20\");if (aLZp5.getUTCMilli" ascii
    $s2  = "function aYv6(aEn4) {eval(\"/*@cc_on var aLZp5 = new Date() @*/\");aLZp5[\"setUTCSeconds\"](\"0\", \"20\");if (aLZp5.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`0` `=` `7`i`Q`A`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\"/`*`@` `}`;`)`0`g`V`R`a`(`0`u`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`b`L`D`a`=`8`g`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = ").toString(10) == \"20\") {var aWXj6 = aEn4[\"split\"](\"`\"); return aWXj6.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\"/`*`@` `}`;`9`f`H`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\"/`*`@` `}`;`6`j`X`W`a` `n`r`u`t`e`r`;`}`;`)`2`h`V`a`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`e`Q`D`a`;`)`2` `,`0`h`M`I`a`(`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`b`L`D`a`=`8`g`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYv6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}