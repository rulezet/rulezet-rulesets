rule sig_20161214_23fa320b2fd8629ff6a6324c8c2aeb5c {
  meta:
    description = "datamaliciousorder - file 20161214_23fa320b2fd8629ff6a6324c8c2aeb5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c87687b2e4bdf0e5f9d64dd419fc741da9088ace2ec129ca594e99605922ae0"

  strings:
    $s1  = "function aWv3(aOGf3) {eval(\"/*@cc_on var aFTs3 = new Date() @*/\");aFTs3[\"setUTCSeconds\"](\"0\", \"20\");if (aFTs3.getUTCMill" ascii
    $s2  = "function aWv3(aOGf3) {eval(\"/*@cc_on var aFTs3 = new Date() @*/\");aFTs3[\"setUTCSeconds\"](\"0\", \"20\");if (aFTs3.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`1`+`1`=`1`p`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\"\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\"}`;`h`t`a`P`t`r`o`h`S`.`4`d`H`a` `n`r`u`t`e`r`;`)`1`d`N`a`(`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`0` `=` `5`d`P`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\"/`*`@` `}`;`)`8`y`N`a`(`1`h`J`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\"/`*`@` `}`;`1`h`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `7`a`G`V`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`o`Y`a`;`)`2` `,`4`d`Y`I`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\"/`*`@` `}`;`)`8`y`N`a`(`1`h`J`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv3(\"/`*`@` `}`;`3`f`G`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}