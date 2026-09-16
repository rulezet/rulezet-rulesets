rule sig_20161215_08fab171532e51cfb1be8cc4df7c96f5 {
  meta:
    description = "datamaliciousorder - file 20161215_08fab171532e51cfb1be8cc4df7c96f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a20cac599c820bfe5d84ac61a25feed1f1724b8c982e35aee593f98f43ea2b6"

  strings:
    $s1  = "function aBs7(aBEs1) {eval(\"/*@cc_on var aSBu7 = new Date() @*/\");aSBu7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSBu7[\"get" ascii
    $s2  = "function aBs7(aBEs1) {eval(\"/*@cc_on var aSBu7 = new Date() @*/\");aSBu7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSBu7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\"/`*`@` `}`;`)`2`t`Z`a`(`2`g`K`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\"/`*`@` `}`;`7`o`Z`H`a` `n`r`u`t`e`r`;`}`;`)`8`e`B`K`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`b`L`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`x`G`U`a` `r`a`v` ` ` ` \"))," ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\"}`;`h`t`a`P`t`r`o`h`S`.`0`k`M`W`a` `n`r`u`t`e`r`;`)`7`r`J`B`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `3`h`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` `" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBs7(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `3`h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}