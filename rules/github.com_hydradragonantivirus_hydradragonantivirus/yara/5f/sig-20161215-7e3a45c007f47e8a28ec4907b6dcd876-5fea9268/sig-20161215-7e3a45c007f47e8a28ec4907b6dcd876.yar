rule sig_20161215_7e3a45c007f47e8a28ec4907b6dcd876 {
  meta:
    description = "datamaliciousorder - file 20161215_7e3a45c007f47e8a28ec4907b6dcd876.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "938747b39adae725ee29eb61ebebdb9a3b42fbe4d0be2b66619a877d083a2047"

  strings:
    $s1  = "function aRHq6(aOOr4) {eval(\"/*@cc_on var aHUg3 = new Date() @*/\");aHUg3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHUg3[\"ge" ascii
    $s2  = "function aRHq6(aOOr4) {eval(\"/*@cc_on var aHUg3 = new Date() @*/\");aHUg3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHUg3[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\"/`*`@` `}`;`4`r`O`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`0` `=` `0`q`J`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`)`\\x22`x`x`1`p`l`e`n`v`d`/`m`o`c`.`t`s`s`e`w`-`a`d`n`a`f" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`v`R`a`;`)`2` `,`2`b`W`a`(`]`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\"/`*`@` `}`;`2`f`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`p" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\"/`*`@` `}`;`3`a`V`K`a` `n`r`u`t`e`r`;`}`;`)`7`k`C`N`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\"/`*`@` `}`;`3`a`V`K`a` `n`r`u`t`e`r`;`}`;`)`7`k`C`N`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`h`V`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\"/`*`@` `}`;`4`r`O`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRHq6(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}