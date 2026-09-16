rule sig_20161214_fa28b1ff841c70ef1c45f5d74eebd0dd {
  meta:
    description = "datamaliciousorder - file 20161214_fa28b1ff841c70ef1c45f5d74eebd0dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f54c92d18ed3a1c53fd6d0973209fef028fc3935fefeeb55ccc47acd7aaaf0e5"

  strings:
    $s1  = "function aPWz6(aUv9) {eval(\"/*@cc_on var aRl8 = new Date() @*/\");aRl8[\"setUTCSeconds\"](\"0\", \"20\");if (aRl8.getUTCMillise" ascii
    $s2  = "function aPWz6(aUv9) {eval(\"/*@cc_on var aRl8 = new Date() @*/\");aRl8[\"setUTCSeconds\"](\"0\", \"20\");if (aRl8.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\"/`*`@` `}`;`)`1`j`D`R`a`(`2`j`L`W`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\"/`*`@` `}`;`7`u`C`a` `n`r`u`t`e`r`;`}`;`)`6`l`E`N`a`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`d`I`a`;`)`2` `,`2`y`A`K`a`(`]" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\"/`*`@` `}`;`9`v`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s10 = "toString(10) == \"20\") {var aCu7 = aUv9[\"split\"](\"`\"); return aCu7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`0` `=` `9`n`B`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\"/`*`@` `}`;`7`u`C`a` `n`r`u`t`e`r`;`}`;`)`6`l`E`N`a`(`]`\\x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `8" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`4`g`D`a` `+` `3`l`C`a`=`7`r`N`H`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\"/`*`@` `}`;`9`v`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`1`+`1`=`1`g`V`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`1`+`1`=`1`g`V`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPWz6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`p`Q`a` `r`a`v` ` ` ` \")), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}