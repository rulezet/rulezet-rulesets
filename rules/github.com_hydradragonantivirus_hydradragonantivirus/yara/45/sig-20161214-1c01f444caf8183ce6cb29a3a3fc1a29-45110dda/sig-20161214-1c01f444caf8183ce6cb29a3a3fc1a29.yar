rule sig_20161214_1c01f444caf8183ce6cb29a3a3fc1a29 {
  meta:
    description = "datamaliciousorder - file 20161214_1c01f444caf8183ce6cb29a3a3fc1a29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fba613518111b58c78205bab30bab32dd17d7267a91ee936830b0b82bf262ffc"

  strings:
    $s1  = "function aLu7(aEj5) {eval(\"/*@cc_on var aIJu8 = new Date() @*/\");aIJu8[\"setUTCSeconds\"](\"0\", \"20\");if (aIJu8.getUTCMilli" ascii
    $s2  = "function aLu7(aEj5) {eval(\"/*@cc_on var aIJu8 = new Date() @*/\");aIJu8[\"setUTCSeconds\"](\"0\", \"20\");if (aIJu8.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`d`N`F`a` `r`a`v` ` ` ` \"))," ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`y`W`N`a`;`)`2` `,`4`a`G`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`0` `=` `8`c`P`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`3`r`X`N`a` `+` `9`c`J`J`a`=`0`r`J`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\"/`*`@` `}`;`0`u`U`K`a` `n`r`u`t`e`r`;`}`;`)`7`v`X`A`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\"/`*`@` `}`;`)`4`u`M`U`a`(`3`l`B`U`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`.`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu7(\"/`*`@` `}`;`5`j`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}