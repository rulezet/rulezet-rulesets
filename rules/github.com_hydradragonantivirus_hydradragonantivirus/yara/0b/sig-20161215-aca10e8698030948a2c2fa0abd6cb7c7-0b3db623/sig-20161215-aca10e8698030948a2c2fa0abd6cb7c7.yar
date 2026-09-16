rule sig_20161215_aca10e8698030948a2c2fa0abd6cb7c7 {
  meta:
    description = "datamaliciousorder - file 20161215_aca10e8698030948a2c2fa0abd6cb7c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac8bc59aba92edd2c5b20ceae149b31faaf8a2a77f2491c9128d5b1bd937351"

  strings:
    $s1  = "function aWl7(aBPg8) {eval(\"/*@cc_on var aEi4 = new Date() @*/\");aEi4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEi4[\"getUTC" ascii
    $s2  = "function aWl7(aBPg8) {eval(\"/*@cc_on var aEi4 = new Date() @*/\");aEi4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEi4[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`a`Y`a`;`)`2` `,`1`d`I`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`a`P`D`a`=`6`u`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"}`;`h`t`a`P`t`r`o`h`S`.`9`e`Q`F`a` `n`r`u`t`e`r`;`)`6`u`O`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`y`O`a` `r`a`v` ` ` ` \")), 1" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\";`0` `=` `9`d`J`S`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`t`N`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`5`e`P`Q`a` `n`r`u`t`e`r`;`}`;`)`0`d`Q`O`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`8`g`P`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`5`e`P`Q`a` `n`r`u`t`e`r`;`}`;`)`0`d`Q`O`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`9`z`K`T`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`)`6`y`E`U`a`(`7`m`T`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"}`;`h`t`a`P`t`r`o`h`S`.`9`e`Q`F`a` `n`r`u`t`e`r`;`)`6`u`O`a`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`8`g`P`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWl7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`a`Y`a`;`)`2` `,`1`d`I`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}