rule sig_20161214_7d89085fdeca7c7759090a201b6eeed4 {
  meta:
    description = "datamaliciousorder - file 20161214_7d89085fdeca7c7759090a201b6eeed4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7b4ded0d48a8ceff0fa1f7d2aa670ccb852e5dff2c4a3339ba98033e24587a2"

  strings:
    $s1  = "function aYf0(aLa7) {eval(\"/*@cc_on var aDh0 = new Date() @*/\");aDh0[\"setUTCSeconds\"](\"0\", \"20\");if (aDh0.getUTCMillisec" ascii
    $s2  = "function aYf0(aLa7) {eval(\"/*@cc_on var aDh0 = new Date() @*/\");aDh0[\"setUTCSeconds\"](\"0\", \"20\");if (aDh0.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`1`+`1`=`7`m`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\"/`*`@` `}`;`7`a`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`0` `=` `0`j`E`G`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`q`B`a`=`5`z`Z`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\"}`;`h`t`a`P`t`r`o`h`S`.`4`d`D`a` `n`r`u`t`e`r`;`)`5`z`Z`H`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\"/`*`@` `}`;`7`w`Q`G`a` `n`r`u`t`e`r`;`}`;`)`0`z`J`a`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`o`I`Y`a` `r`a`v` ` ` ` \"))," ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `2`h`Z`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\"/`*`@` `}`;`)`8`k`D`a`(`9`i`Z`J`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}