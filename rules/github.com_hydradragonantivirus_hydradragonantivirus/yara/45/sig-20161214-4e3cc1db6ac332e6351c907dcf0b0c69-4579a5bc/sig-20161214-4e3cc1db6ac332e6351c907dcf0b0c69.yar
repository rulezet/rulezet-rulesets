rule sig_20161214_4e3cc1db6ac332e6351c907dcf0b0c69 {
  meta:
    description = "datamaliciousorder - file 20161214_4e3cc1db6ac332e6351c907dcf0b0c69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "116bbcd1f2fb5578f742d2bb7453365d779e78a206774d6f77fe73786e4baadf"

  strings:
    $s1  = "function aLId0(aURn9) {eval(\"/*@cc_on var aRt2 = new Date() @*/\");aRt2[\"setUTCSeconds\"](\"0\", \"20\");if (aRt2.getUTCMillis" ascii
    $s2  = "function aLId0(aURn9) {eval(\"/*@cc_on var aRt2 = new Date() @*/\");aRt2[\"setUTCSeconds\"](\"0\", \"20\");if (aRt2.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`x`Y`a`=`2`v`C" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\"/`*`@` `}`;`9`n`R`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`0` `=` `3`r`S`Z`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\"/`*`@` `}`;`)`8`d`Z`a`(`0`p`H`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\"/`*`@` `}`;`1`m`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\"/`*`@` `}`;`9`n`R`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`1`y`P`a` `+` `3`j`V`X`a`=`6`x`Y`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLId0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`x`Y`a`=`2`v`C" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}