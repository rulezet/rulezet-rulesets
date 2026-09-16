rule sig_20161215_f392f1a8ec967293745c85ceac798634 {
  meta:
    description = "datamaliciousorder - file 20161215_f392f1a8ec967293745c85ceac798634.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "903984d9d260f64545efc6b2549f1cf59cb229357800ccfc47d6c1cc3503ac1a"

  strings:
    $s1  = "function aNHu2(aAw5) {eval(\"/*@cc_on var aHJq7 = new Date() @*/\");aHJq7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHJq7[\"get" ascii
    $s2  = "function aNHu2(aAw5) {eval(\"/*@cc_on var aHJq7 = new Date() @*/\");aHJq7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHJq7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`q`L`W`a`;`)`2` `,`7`h`A`a`(`]" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\"/`*`@` `}`;`)`8`s`B`a`(`9`e`T`M`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`e`I`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\"/`*`@` `}`;`0`a`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`h" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\"/`*`@` `}`;`)`8`s`B`a`(`9`e`T`M`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\"/`*`@` `}`;`8`h`U`K`a` `n`r`u`t`e`r`;`}`;`)`7`z`O`Z`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\"/`*`@` `}`;`8`h`U`K`a` `n`r`u`t`e`r`;`}`;`)`7`z`O`Z`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`0` `=` `2`i`W`B`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`g`R`J`a` `r`a`v` ` ` ` \"))" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNHu2(\"}`;`h`t`a`P`t`r`o`h`S`.`9`s`U`K`a` `n`r`u`t`e`r`;`)`3`j`P`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}