rule sig_20161214_3f8483479df2a8c3d8a9a7c3605b70df {
  meta:
    description = "datamaliciousorder - file 20161214_3f8483479df2a8c3d8a9a7c3605b70df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a06f7834fc8b5b88893cf7cce9037c275ffded5a7905fca1a849953a6865a58c"

  strings:
    $s1  = "function aUh5(aRFd9) {eval(\"/*@cc_on var aDu6 = new Date() @*/\");aDu6[\"setUTCSeconds\"](\"0\", \"20\");if (aDu6.getUTCMillise" ascii
    $s2  = "function aUh5(aRFd9) {eval(\"/*@cc_on var aDu6 = new Date() @*/\");aDu6[\"setUTCSeconds\"](\"0\", \"20\");if (aDu6.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\"/`*`@` `}`;`7`c`Z`a` `n`r`u`t`e`r`;`}`;`)`4`m`Z`a`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `0`w`U`X`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "toString(10) == \"20\") {var aZc7 = aRFd9[\"split\"](\"`\"); return aZc7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`1`+`1`=`8`x`C`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`k`G`F`a`=`7`n`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\"}`;`h`t`a`P`t`r`o`h`S`.`1`m`R`a` `n`r`u`t`e`r`;`)`7`n`S`T`a`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUh5(\";`1`+`1`=`8`x`C`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}