rule sig_20161214_ebbec1e3aa5e25bd740b275e9f7ea51c {
  meta:
    description = "datamaliciousorder - file 20161214_ebbec1e3aa5e25bd740b275e9f7ea51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27db4ef5a844ed63cb7c8658e7ed753c0cbb9ebe5db900b0e9d18f491cef2fc1"

  strings:
    $s1  = "function aEu0(aYj7) {eval(\"/*@cc_on var aXq9 = new Date() @*/\");aXq9[\"setUTCSeconds\"](\"0\", \"20\");if (aXq9.getUTCMillisec" ascii
    $s2  = "function aEu0(aYj7) {eval(\"/*@cc_on var aXq9 = new Date() @*/\");aXq9[\"setUTCSeconds\"](\"0\", \"20\");if (aXq9.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`p`T`a`;`)`2` `,`6`l`F`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`1`+`1`=`8`u`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\"/`*`@` `}`;`4`g`I`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\"/`*`@` `}`;`7`j`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`p`T`a`;`)`2` `,`6`l`F`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\"/`*`@` `}`;`6`g`I`a` `n`r`u`t`e`r`;`}`;`)`0`r`S`a`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\"/`*`@` `}`;`7`j`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`b`W`a` `r`a`v` ` ` ` \")), 1" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`0` `=` `5`y`Y`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEu0(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}