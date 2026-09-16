rule sig_20161214_ca12144fb15916812d498fb7549dd1c3 {
  meta:
    description = "datamaliciousorder - file 20161214_ca12144fb15916812d498fb7549dd1c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bce452de05e2b2cece9cf44cc8696b8aa0fde91229ebbabfdfafffb5776e0b58"

  strings:
    $s1  = "function aEj5(aVBn0) {eval(\"/*@cc_on var aKk9 = new Date() @*/\");aKk9[\"setUTCSeconds\"](\"0\", \"20\");if (aKk9.getUTCMillise" ascii
    $s2  = "function aEj5(aVBn0) {eval(\"/*@cc_on var aKk9 = new Date() @*/\");aKk9[\"setUTCSeconds\"](\"0\", \"20\");if (aKk9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\"/`*`@` `}`;`0`n`B`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`t`P`a` `r`a`v` ` ` ` \")), 1" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`d`C`T`a`;`)`2` `,`5`z`S`L`a`(`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`5`n`Q`a` `+` `6`y`T`a`=`6`j`Q`T`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "toString(10) == \"20\") {var aGr8 = aVBn0[\"split\"](\"`\"); return aGr8.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\"}`;`h`t`a`P`t`r`o`h`S`.`1`m`J`Z`a` `n`r`u`t`e`r`;`)`3`r`T`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`j`Q`T`a`=`3`r`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\"/`*`@` `}`;`)`8`h`N`Z`a`(`6`s`P`W`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\"}`;`h`t`a`P`t`r`o`h`S`.`1`m`J`Z`a` `n`r`u`t`e`r`;`)`3`r`T`X`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj5(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}