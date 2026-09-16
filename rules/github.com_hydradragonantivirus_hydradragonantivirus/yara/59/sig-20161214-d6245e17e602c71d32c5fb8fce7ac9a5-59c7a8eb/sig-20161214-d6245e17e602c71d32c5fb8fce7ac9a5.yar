rule sig_20161214_d6245e17e602c71d32c5fb8fce7ac9a5 {
  meta:
    description = "datamaliciousorder - file 20161214_d6245e17e602c71d32c5fb8fce7ac9a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "712ced18a3614ee2dfbae60fabf1209691d4ca636d808ac47e520748a06d0bb5"

  strings:
    $s1  = "function aWSx7(aBb0) {eval(\"/*@cc_on var aMQe4 = new Date() @*/\");aMQe4[\"setUTCSeconds\"](\"0\", \"20\");if (aMQe4.getUTCMill" ascii
    $s2  = "function aWSx7(aBb0) {eval(\"/*@cc_on var aMQe4 = new Date() @*/\");aMQe4[\"setUTCSeconds\"](\"0\", \"20\");if (aMQe4.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`1`+`1`=`7`h`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`1`+`1`=`7`h`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\"/`*`@` `}`;`0`b`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`o`Q`a`;`)`2` `,`0`h`K`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\"}`;`h`t`a`P`t`r`o`h`S`.`6`i`P`Y`a` `n`r`u`t`e`r`;`)`4`r`A`U" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\"/`*`@` `}`;`0`b`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\"/`*`@` `}`;`5`k`C`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\"/`*`@` `}`;`6`m`K`a` `n`r`u`t`e`r`;`}`;`)`8`h`I`R`a`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWSx7(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`." ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}