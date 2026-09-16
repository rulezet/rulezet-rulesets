rule sig_20161215_ef1415a4e8b13425afee8ce6e6caf13d {
  meta:
    description = "datamaliciousorder - file 20161215_ef1415a4e8b13425afee8ce6e6caf13d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02a1a4ffe53204fd9dcb8571138aff022b7948680d0ee8ff84f4f6c9bc07064d"

  strings:
    $s1  = "function aJYz9(aLk2) {eval(\"/*@cc_on var aBSg9 = new Date() @*/\");aBSg9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBSg9[\"get" ascii
    $s2  = "function aJYz9(aLk2) {eval(\"/*@cc_on var aBSg9 = new Date() @*/\");aBSg9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBSg9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\"/`*`@` `}`;`2`k`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\"/`*`@` `}`;`5`w`K`a` `n`r`u`t`e`r`;`}`;`)`8`j`Y`a`(`]`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\"/`*`@` `}`;`3`r`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`y" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`z`R`D`a`=`1`j" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\"/`*`@` `}`;`3`r`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`y" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\"/`*`@` `}`;`2`k`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`z`R`D`a`=`1`j" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`2`v`S`a` `+` `4`b`A`Y`a`=`2`z`R`D`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`v`M`F`a` `r`a`v` `;" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`1`+`1`=`9`w`C`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`v`M`F`a` `r`a`v` `;" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJYz9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`t`C`U`a`;`)`2` `,`0`t`U`T`a`(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}