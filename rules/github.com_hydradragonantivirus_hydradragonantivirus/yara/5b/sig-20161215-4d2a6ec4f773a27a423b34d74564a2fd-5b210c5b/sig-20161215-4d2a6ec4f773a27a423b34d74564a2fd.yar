rule sig_20161215_4d2a6ec4f773a27a423b34d74564a2fd {
  meta:
    description = "datamaliciousorder - file 20161215_4d2a6ec4f773a27a423b34d74564a2fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a40ed18e56dbfe713035faaaf1e08d45631f60b75e7be19484078329b1d65f3"

  strings:
    $s1  = "function aTQx5(aWq6) {eval(\"/*@cc_on var aLd7 = new Date() @*/\");aLd7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLd7[\"getUTC" ascii
    $s2  = "function aTQx5(aWq6) {eval(\"/*@cc_on var aLd7 = new Date() @*/\");aLd7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLd7[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\"/`*`@` `}`;`7`r`I`a` `n`r`u`t`e`r`;`}`;`)`8`m`B`S`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\"/`*`@` `}`;`7`r`I`a` `n`r`u`t`e`r`;`}`;`)`8`m`B`S`a`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`f`W`a`=`8`q`A" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\"/`*`@` `}`;`)`2`c`R`a`(`8`x`F`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\"/`*`@` `}`;`6`q`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`0` `=` `7`i`W`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `3`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\"/`*`@` `}`;`6`q`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`d`P`D`a`;`)`2` `,`8`r`H`a`(`]" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`f`W`a`=`8`q`A" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTQx5(\"/`*`@` `}`;`7`z`O`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}