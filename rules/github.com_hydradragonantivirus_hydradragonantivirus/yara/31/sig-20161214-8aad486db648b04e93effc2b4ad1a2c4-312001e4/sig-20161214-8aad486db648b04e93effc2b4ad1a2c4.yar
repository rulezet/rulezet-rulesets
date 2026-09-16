rule sig_20161214_8aad486db648b04e93effc2b4ad1a2c4 {
  meta:
    description = "datamaliciousorder - file 20161214_8aad486db648b04e93effc2b4ad1a2c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c38974b2e90df2d8e57847c300e0da6b6054ab009cecd252e119c59a565d71db"

  strings:
    $s1  = "function aNu7(aYYg5) {eval(\"/*@cc_on var aFw6 = new Date() @*/\");aFw6[\"setUTCSeconds\"](\"0\", \"20\");if (aFw6.getUTCMillise" ascii
    $s2  = "function aNu7(aYYg5) {eval(\"/*@cc_on var aFw6 = new Date() @*/\");aFw6[\"setUTCSeconds\"](\"0\", \"20\");if (aFw6.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\"}`;`h`t`a`P`t`r`o`h`S`.`4`h`T`a` `n`r`u`t`e`r`;`)`0`q`P`Z`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\"}`;`h`t`a`P`t`r`o`h`S`.`4`h`T`a` `n`r`u`t`e`r`;`)`0`q`P`Z`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`j`L`a`=`0`q`P`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`p`P`a`;`)`2` `,`0`z`Y`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`)`\\x22`d`w`n`h`3`c`m`/`m`o`c`.`i`a`i`d`u`w`\\x22` `+` `5`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\"/`*`@` `}`;`)`8`y`B`G`a`(`6`p`M`Y`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`r`X`a` `r`a`v` ` ` ` \")), 1" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`p`P`a`;`)`2` `,`0`z`Y`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNu7(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}