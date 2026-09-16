rule sig_20161214_07872aafcc36c8c3669ef36d4c6511e9 {
  meta:
    description = "datamaliciousorder - file 20161214_07872aafcc36c8c3669ef36d4c6511e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a62c1a8c498e65a66ed5d5446f2c20f31e05563fe4b27eb4fb16e9d3adf15e7"

  strings:
    $s1  = "function aJc0(aEAj1) {eval(\"/*@cc_on var aJj9 = new Date() @*/\");aJj9[\"setUTCSeconds\"](\"0\", \"20\");if (aJj9.getUTCMillise" ascii
    $s2  = "function aJc0(aEAj1) {eval(\"/*@cc_on var aJj9 = new Date() @*/\");aJj9[\"setUTCSeconds\"](\"0\", \"20\");if (aJj9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`3`d`G`a` `+` `7`b`O`N`a`=`1`u`O`F`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`v`T`E`a` `n`r`u`t`e`r`;`)`9`v`H`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`u`O`F`a`=`9`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`1`+`1`=`7`h`X`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\"/`*`@` `}`;`3`x`K`a` `n`r`u`t`e`r`;`}`;`)`6`m`C`V`a`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\"/`*`@` `}`;`1`j`A`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`j`L`a` `r`a`v` ` ` ` \")), 1" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`t`T`J`a`;`)`2` `,`0`n`E`N`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\"/`*`@` `}`;`)`9`k`I`a`(`3`g`L`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJc0(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}