rule sig_20161214_56f777656691a54fe29c430e8691144d {
  meta:
    description = "datamaliciousorder - file 20161214_56f777656691a54fe29c430e8691144d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d23fe9f6f204e1e63a174727a2ca12527ad03febd9d829d3075dc59079b4d753"

  strings:
    $s1  = "function aPPg1(aBb5) {eval(\"/*@cc_on var aOv1 = new Date() @*/\");aOv1[\"setUTCSeconds\"](\"0\", \"20\");if (aOv1.getUTCMillise" ascii
    $s2  = "function aPPg1(aBb5) {eval(\"/*@cc_on var aOv1 = new Date() @*/\");aOv1[\"setUTCSeconds\"](\"0\", \"20\");if (aOv1.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\"/`*`@` `}`;`)`4`s`Q`a`(`3`q`R`O`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`1`+`1`=`8`j`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\"/`*`@` `}`;`)`4`s`Q`a`(`3`q`R`O`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\"/`*`@` `}`;`5`b`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "toString(10) == \"20\") {var aVs9 = aBb5[\"split\"](\"`\"); return aVs9.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`0` `=` `5`o`M`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\"}`;`h`t`a`P`t`r`o`h`S`.`3`o`O`a` `n`r`u`t`e`r`;`)`3`p`X`a`(" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\"/`*`@` `}`;`9`s`V`a` `n`r`u`t`e`r`;`}`;`)`3`t`A`S`a`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPPg1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`o`R`a` `r`a`v` ` ` ` \")), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}