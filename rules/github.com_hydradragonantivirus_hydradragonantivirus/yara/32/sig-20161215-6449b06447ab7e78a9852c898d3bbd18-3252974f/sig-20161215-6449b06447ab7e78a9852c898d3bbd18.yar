rule sig_20161215_6449b06447ab7e78a9852c898d3bbd18 {
  meta:
    description = "datamaliciousorder - file 20161215_6449b06447ab7e78a9852c898d3bbd18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03e3ce260512df13468127590f5fe3335fbdc987cefbae0d9dd52edb93a8f5b1"

  strings:
    $s1  = "function aMh8(aDYp7) {eval(\"/*@cc_on var aJUr2 = new Date() @*/\");aJUr2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJUr2[\"get" ascii
    $s2  = "function aMh8(aDYp7) {eval(\"/*@cc_on var aJUr2 = new Date() @*/\");aJUr2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJUr2[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\"/`*`@` `}`;`3`a`H`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `3`h`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\"}`;`h`t`a`P`t`r`o`h`S`.`0`c`G`a` `n`r`u`t`e`r`;`)`7`s`D`K`a`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\"/`*`@` `}`;`3`b`F`a` `n`r`u`t`e`r`;`}`;`)`1`h`D`a`(`]`\\x22`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\"/`*`@` `}`;`7`p`Y`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`0` `=` `5`x`H`P`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`b`S`a`;`)`2` `,`3`r`X`J`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\"/`*`@` `}`;`3`a`H`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\"}`;`h`t`a`P`t`r`o`h`S`.`0`c`G`a` `n`r`u`t`e`r`;`)`7`s`D`K`a`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMh8(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}