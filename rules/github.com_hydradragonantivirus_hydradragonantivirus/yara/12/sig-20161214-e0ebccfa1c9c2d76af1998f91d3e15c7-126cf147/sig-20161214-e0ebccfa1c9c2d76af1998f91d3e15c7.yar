rule sig_20161214_e0ebccfa1c9c2d76af1998f91d3e15c7 {
  meta:
    description = "datamaliciousorder - file 20161214_e0ebccfa1c9c2d76af1998f91d3e15c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8abd4b40a6f6cc38a7aaced757907fc7364bd622ccb94b78ecd046dc1de2870a"

  strings:
    $s1  = "function aQu0(aBa2) {eval(\"/*@cc_on var aMDn6 = new Date() @*/\");aMDn6[\"setUTCSeconds\"](\"0\", \"20\");if (aMDn6.getUTCMilli" ascii
    $s2  = "function aQu0(aBa2) {eval(\"/*@cc_on var aMDn6 = new Date() @*/\");aMDn6[\"setUTCSeconds\"](\"0\", \"20\");if (aMDn6.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`h`X`C`a`;`)`2` `,`6`g`E`W`a`(`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\"/`*`@` `}`;`0`h`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`b`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\"/`*`@` `}`;`1`a`I`B`a` `n`r`u`t`e`r`;`}`;`)`1`e`I`a`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `7`n`Q`X`a`(`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\"/`*`@` `}`;`2`a`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`g`E`a`=`9`g`B`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\"/`*`@` `}`;`)`5`m`Y`I`a`(`9`w`J`X`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`1`+`1`=`7`y`X`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `7`n`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQu0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`h`X`C`a`;`)`2` `,`6`g`E`W`a`(`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}