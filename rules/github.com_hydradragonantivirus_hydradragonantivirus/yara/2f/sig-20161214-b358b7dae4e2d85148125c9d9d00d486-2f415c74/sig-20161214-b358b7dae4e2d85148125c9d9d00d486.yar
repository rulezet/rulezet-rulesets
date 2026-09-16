rule sig_20161214_b358b7dae4e2d85148125c9d9d00d486 {
  meta:
    description = "datamaliciousorder - file 20161214_b358b7dae4e2d85148125c9d9d00d486.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff8e400c7bc89975fef93da27e8e312024ed4213e44533e099d93ba88344433d"

  strings:
    $s1  = "function aYEu8(aLa9) {eval(\"/*@cc_on var aNMi3 = new Date() @*/\");aNMi3[\"setUTCSeconds\"](\"0\", \"20\");if (aNMi3.getUTCMill" ascii
    $s2  = "function aYEu8(aLa9) {eval(\"/*@cc_on var aNMi3 = new Date() @*/\");aNMi3[\"setUTCSeconds\"](\"0\", \"20\");if (aNMi3.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"}`;`h`t`a`P`t`r`o`h`S`.`0`z`V`a` `n`r`u`t`e`r`;`)`8`d`L`a`(" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"/`*`@` `}`;`9`a`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`j`H`Z`a`;`)`2` `,`0`c`E`a`(`]" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"}`;`h`t`a`P`t`r`o`h`S`.`0`z`V`a` `n`r`u`t`e`r`;`)`8`d`L`a`(" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`i`C`Q`a`=`8`d" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"/`*`@` `}`;`9`a`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"/`*`@` `}`;`)`6`g`L`G`a`(`9`e`X`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`1`+`1`=`5`x`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"/`*`@` `}`;`5`b`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`n" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`0` `=` `8`d`D`T`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`8`d`V`a` `+` `0`a`F`T`a`=`4`i`C`Q`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`i`C`Q`a`=`8`d" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYEu8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}