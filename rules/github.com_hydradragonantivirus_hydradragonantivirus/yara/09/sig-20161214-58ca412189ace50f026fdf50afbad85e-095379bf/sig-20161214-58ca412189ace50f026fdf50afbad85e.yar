rule sig_20161214_58ca412189ace50f026fdf50afbad85e {
  meta:
    description = "datamaliciousorder - file 20161214_58ca412189ace50f026fdf50afbad85e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e828eaf50aa5959d9d4c0899867aa15119da145715e1e1cf14a1951419bff19"

  strings:
    $s1  = "function aJs5(aTEb0) {eval(\"/*@cc_on var aDp9 = new Date() @*/\");aDp9[\"setUTCSeconds\"](\"0\", \"20\");if (aDp9.getUTCMillise" ascii
    $s2  = "function aJs5(aTEb0) {eval(\"/*@cc_on var aDp9 = new Date() @*/\");aDp9[\"setUTCSeconds\"](\"0\", \"20\");if (aDp9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\"/`*`@` `}`;`1`d`L`I`a` `n`r`u`t`e`r`;`}`;`)`6`x`I`a`(`]`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `2`j`P`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\"/`*`@` `}`;`0`b`E`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`e`H`a`=`7`q`R`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`q`U`Q`a`;`)`2` `,`7`f`C`T`a`(`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\"/`*`@` `}`;`)`7`z`G`E`a`(`0`w`H`D`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\"/`*`@` `}`;`0`s`W`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`q`D`F`a` `r`a`v` ` ` ` \"))," ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJs5(\";`1`+`1`=`8`i`S`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}