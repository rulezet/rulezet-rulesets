rule sig_20161215_2a4883f93e7834491104421145b44aa0 {
  meta:
    description = "datamaliciousorder - file 20161215_2a4883f93e7834491104421145b44aa0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca0d49b03ccc1d83add32207704154d8550e8e8f03b7c8595eb2a514ac39d449"

  strings:
    $s1  = "function aTZr8(aLy1) {eval(\"/*@cc_on var aGs1 = new Date() @*/\");aGs1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGs1[\"getUTC" ascii
    $s2  = "function aTZr8(aLy1) {eval(\"/*@cc_on var aGs1 = new Date() @*/\");aGs1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGs1[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`)`\\x22`z`x`p`o`t`l`/`l`p`.`o`t`u`a`-`a`f`l`a`\\x22` `+` " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`)`\\x22`n`z`i`c`m`h`2`m`/`m`o`c`.`p`a`s`a`k`n`a`k`a`t`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\"}`;`h`t`a`P`t`r`o`h`S`.`2`d`O`a` `n`r`u`t`e`r`;`)`2`a`M`H`a" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`b`P`W`a`;`)`2` `,`2`p`N`a`(`]" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\"/`*`@` `}`;`5`q`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`b" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`0` `=` `0`x`K`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\"}`;`h`t`a`P`t`r`o`h`S`.`2`d`O`a` `n`r`u`t`e`r`;`)`2`a`M`H`a" ascii
    $s14 = "s\"]()[\"toString\"](10) == \"20\") {var aTu6 = aLy1[\"split\"](\"`\"); return aTu6[\"reverse\"]().join(\"\");} else return \"\"" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`o`V`W`a` `r`a`v` ` ` ` \"))" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\"/`*`@` `}`;`6`u`T`a` `n`r`u`t`e`r`;`}`;`)`9`l`W`a`(`]`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\"/`*`@` `}`;`1`y`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZr8(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}