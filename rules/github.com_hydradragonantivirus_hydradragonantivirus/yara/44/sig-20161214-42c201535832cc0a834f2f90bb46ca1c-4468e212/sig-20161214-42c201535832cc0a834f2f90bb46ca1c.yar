rule sig_20161214_42c201535832cc0a834f2f90bb46ca1c {
  meta:
    description = "datamaliciousorder - file 20161214_42c201535832cc0a834f2f90bb46ca1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ba89f556f978a636185a571d60e54ecddc9378e42b2d99c39fb5dfa276a2f68"

  strings:
    $s1  = "function aEj4(aYXd3) {eval(\"/*@cc_on var aRz5 = new Date() @*/\");aRz5[\"setUTCSeconds\"](\"0\", \"20\");if (aRz5.getUTCMillise" ascii
    $s2  = "function aEj4(aYXd3) {eval(\"/*@cc_on var aRz5 = new Date() @*/\");aRz5[\"setUTCSeconds\"](\"0\", \"20\");if (aRz5.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`1`+`1`=`1`l`M`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\"/`*`@` `}`;`1`j`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`2`x`Y`Y`a` `+` `2`i`Y`J`a`=`7`r`J`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`r`J`a`=`5`p`U`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`o`F`a` `n`r`u`t`e`r`;`)`5`p`U`H`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\"/`*`@` `}`;`)`5`w`T`a`(`4`l`K`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\"/`*`@` `}`;`7`l`O`P`a` `n`r`u`t`e`r`;`}`;`)`4`f`W`a`(`]`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEj4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`r`J`a`=`5`p`U`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}