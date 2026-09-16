rule sig_20161214_e68fab1dbb485a26c945dec47c44965e {
  meta:
    description = "datamaliciousorder - file 20161214_e68fab1dbb485a26c945dec47c44965e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19397b45678147e5c82d2417b355c9086771ef235593941859ccdc9077d0fdc8"

  strings:
    $s1  = "function aKNb2(aZFh0) {eval(\"/*@cc_on var aXDc9 = new Date() @*/\");aXDc9[\"setUTCSeconds\"](\"0\", \"20\");if (aXDc9.getUTCMil" ascii
    $s2  = "function aKNb2(aZFh0) {eval(\"/*@cc_on var aXDc9 = new Date() @*/\");aXDc9[\"setUTCSeconds\"](\"0\", \"20\");if (aXDc9.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`k`L`O`a`;`)`2` `,`6`o`V`a`(`]" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`0` `=` `8`b`Q`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\"/`*`@` `}`;`)`2`v`P`D`a`(`3`b`P`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\"/`*`@` `}`;`0`n`B`T`a` `n`r`u`t`e`r`;`}`;`)`4`x`F`A`a`(`]`" ascii
    $s9  = "s().toString(10) == \"20\") {var aTBn0 = aZFh0[\"split\"](\"`\"); return aTBn0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\"/`*`@` `}`;`6`d`B`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\"}`;`h`t`a`P`t`r`o`h`S`.`2`k`O`a` `n`r`u`t`e`r`;`)`6`m`F`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `9`b" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`1`+`1`=`9`n`H`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`1`+`1`=`9`n`H`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKNb2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}