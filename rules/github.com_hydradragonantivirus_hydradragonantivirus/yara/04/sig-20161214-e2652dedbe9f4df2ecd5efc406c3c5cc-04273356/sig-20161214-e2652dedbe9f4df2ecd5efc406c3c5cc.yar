rule sig_20161214_e2652dedbe9f4df2ecd5efc406c3c5cc {
  meta:
    description = "datamaliciousorder - file 20161214_e2652dedbe9f4df2ecd5efc406c3c5cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9307928f171ed0eb4095ed785899e84c8a779be83b5a0e74413c916615370114"

  strings:
    $s1  = "function aXx3(aYd2) {eval(\"/*@cc_on var aPn3 = new Date() @*/\");aPn3[\"setUTCSeconds\"](\"0\", \"20\");if (aPn3.getUTCMillisec" ascii
    $s2  = "function aXx3(aYd2) {eval(\"/*@cc_on var aPn3 = new Date() @*/\");aPn3[\"setUTCSeconds\"](\"0\", \"20\");if (aPn3.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`p`B`a`;`)`2` `,`8`p`G`G`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`1`+`1`=`8`n`X`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\"/`*`@` `}`;`2`d`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\"/`*`@` `}`;`2`d`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s8  = "oString(10) == \"20\") {var aKDw2 = aYd2[\"split\"](\"`\"); return aKDw2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\"/`*`@` `}`;`2`w`D`K`a` `n`r`u`t`e`r`;`}`;`)`1`v`U`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`0` `=` `9`n`I`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\"}`;`h`t`a`P`t`r`o`h`S`.`6`i`O`N`a` `n`r`u`t`e`r`;`)`5`n`R`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`v`X`U`a`=`5`n`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx3(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}