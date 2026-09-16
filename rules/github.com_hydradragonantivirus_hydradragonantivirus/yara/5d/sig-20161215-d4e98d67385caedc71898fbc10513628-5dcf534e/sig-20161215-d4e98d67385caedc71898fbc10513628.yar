rule sig_20161215_d4e98d67385caedc71898fbc10513628 {
  meta:
    description = "datamaliciousorder - file 20161215_d4e98d67385caedc71898fbc10513628.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bb780ca6330c02cdeda132a9fc99824bc36fffbb708ee31960f6c53f3e467f0"

  strings:
    $s1  = "function aCSb4(aHQk9) {eval(\"/*@cc_on var aKIz3 = new Date() @*/\");aKIz3[\"setUTCSeconds\"](\"0\", \"20\");if (aKIz3.getUTCMil" ascii
    $s2  = "function aCSb4(aHQk9) {eval(\"/*@cc_on var aKIz3 = new Date() @*/\");aKIz3[\"setUTCSeconds\"](\"0\", \"20\");if (aKIz3.getUTCMil" ascii
    $s3  = "s().toString(10) == \"20\") {var aPFv3 = aHQk9[\"split\"](\"`\"); return aPFv3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"/`*`@` `}`;`3`v`F`P`a` `n`r`u`t`e`r`;`}`;`)`4`f`Y`a`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"}`;`h`t`a`P`t`r`o`h`S`.`3`d`I`a` `n`r`u`t`e`r`;`)`9`i`S`a`(" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`b`Z`a`;`)`2` `,`6`n`H`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\";`0` `=` `2`s`K`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`b`Z`a`;`)`2` `,`6`n`H`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\";`1`+`1`=`8`w`X`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"/`*`@` `}`;`)`7`l`L`B`a`(`9`a`E`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\";`5`e`S`a` `+` `0`l`C`X`a`=`2`f`L`H`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"/`*`@` `}`;`9`k`Q`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\"/`*`@` `}`;`9`k`Q`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCSb4(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}