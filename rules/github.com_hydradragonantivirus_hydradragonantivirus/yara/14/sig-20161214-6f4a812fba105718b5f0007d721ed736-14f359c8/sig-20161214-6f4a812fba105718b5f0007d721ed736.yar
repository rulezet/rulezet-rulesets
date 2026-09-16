rule sig_20161214_6f4a812fba105718b5f0007d721ed736 {
  meta:
    description = "datamaliciousorder - file 20161214_6f4a812fba105718b5f0007d721ed736.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc5e0ee146c5d43eca545f195a127ad4e2d1f4c8583cd6f928ca4f1511b47b83"

  strings:
    $s1  = "function aHGk7(aKNm3) {eval(\"/*@cc_on var aIWo5 = new Date() @*/\");aIWo5[\"setUTCSeconds\"](\"0\", \"20\");if (aIWo5.getUTCMil" ascii
    $s2  = "function aHGk7(aKNm3) {eval(\"/*@cc_on var aIWo5 = new Date() @*/\");aIWo5[\"setUTCSeconds\"](\"0\", \"20\");if (aIWo5.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"/`*`@` `}`;`4`w`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`m" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"/`*`@` `}`;`)`3`p`J`a`(`1`k`W`C`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `8`p`X`a`(`h" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `8`p" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`f`U`Q`a`;`)`2` `,`4`v`Y`a`(`]" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`0` `=` `1`n`W`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"}`;`h`t`a`P`t`r`o`h`S`.`8`b`D`a` `n`r`u`t`e`r`;`)`0`g`U`a`(" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"}`;`h`t`a`P`t`r`o`h`S`.`8`b`D`a` `n`r`u`t`e`r`;`)`0`g`U`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`1`+`1`=`4`p`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `8`p" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"/`*`@` `}`;`6`q`G`a` `n`r`u`t`e`r`;`}`;`)`0`y`Q`a`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"/`*`@` `}`;`)`3`p`J`a`(`1`k`W`C`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`c`I`Z`a`=`0`g" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHGk7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}