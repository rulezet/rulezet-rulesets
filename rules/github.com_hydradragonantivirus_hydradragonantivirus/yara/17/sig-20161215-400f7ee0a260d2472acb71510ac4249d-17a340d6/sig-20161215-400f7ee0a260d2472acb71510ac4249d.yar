rule sig_20161215_400f7ee0a260d2472acb71510ac4249d {
  meta:
    description = "datamaliciousorder - file 20161215_400f7ee0a260d2472acb71510ac4249d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf82da41f274b9eaa743977fb178d5986cc042a2832ec9cefcd502c60d1e3b00"

  strings:
    $s1  = "function aTUh2(aFe9) {eval(\"/*@cc_on var aIq6 = new Date() @*/\");aIq6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIq6[\"getUTC" ascii
    $s2  = "function aTUh2(aFe9) {eval(\"/*@cc_on var aIq6 = new Date() @*/\");aIq6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIq6[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\"/`*`@` `}`;`9`e`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`1`+`1`=`0`y`H`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\"/`*`@` `}`;`2`l`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`v" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`)`\\x22`j`o`o`6`p`c`9`w`z`n`/`m`o`c`.`e`c`i`-`p`e`e`d`.`n" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`2`q`F`J`a` `+` `4`f`N`a`=`2`a`G`E`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\"/`*`@` `}`;`6`t`Y`a` `n`r`u`t`e`r`;`}`;`)`3`f`M`a`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`s`T`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`v`M`a`;`)`2` `,`0`f`V`G`a`(`]" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\"/`*`@` `}`;`9`e`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTUh2(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}