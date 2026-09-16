rule sig_20161215_c0b6d636e4de86c0459d72892cfd2607 {
  meta:
    description = "datamaliciousorder - file 20161215_c0b6d636e4de86c0459d72892cfd2607.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03f63beab9d5d37a3e5300d888d66145ec6586fac580095532f6255eaeb8cab8"

  strings:
    $s1  = "function aZj6(aAXa9) {eval(\"/*@cc_on var aPt0 = new Date() @*/\");aPt0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPt0[\"getUTC" ascii
    $s2  = "function aZj6(aAXa9) {eval(\"/*@cc_on var aPt0 = new Date() @*/\");aPt0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPt0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`6`m`N`a` `+` `3`p`G`a`=`8`t`N`J`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`b`S`a`;`)`2` `,`6`j`X`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\"/`*`@` `}`;`)`3`g`R`T`a`(`9`t`B`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\"/`*`@` `}`;`9`j`C`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\"}`;`h`t`a`P`t`r`o`h`S`.`5`c`C`a` `n`r`u`t`e`r`;`)`6`x`Z`a`(`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`l`I`V`a` `r`a`v` `;`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`)`\\x22`3`2`i`t`s`/`m`o`c`.`s`b`e`w`0`5`.`e`c`i`v`d`a`l`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZj6(\"/`*`@` `}`;`9`a`X`A`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}