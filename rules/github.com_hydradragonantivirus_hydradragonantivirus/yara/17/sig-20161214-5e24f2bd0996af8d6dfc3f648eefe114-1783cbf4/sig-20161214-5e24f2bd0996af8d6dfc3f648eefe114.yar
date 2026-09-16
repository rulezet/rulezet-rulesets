rule sig_20161214_5e24f2bd0996af8d6dfc3f648eefe114 {
  meta:
    description = "datamaliciousorder - file 20161214_5e24f2bd0996af8d6dfc3f648eefe114.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "415e7ae08676fe98e0d6bc5c18ee48488c99386dd47a657e8592d474f9de246b"

  strings:
    $s1  = "function aVc6(aEMv1) {eval(\"/*@cc_on var aRx1 = new Date() @*/\");aRx1[\"setUTCSeconds\"](\"0\", \"20\");if (aRx1.getUTCMillise" ascii
    $s2  = "function aVc6(aEMv1) {eval(\"/*@cc_on var aRx1 = new Date() @*/\");aRx1[\"setUTCSeconds\"](\"0\", \"20\");if (aRx1.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\"/`*`@` `}`;`)`3`o`N`N`a`(`3`q`S`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\"/`*`@` `}`;`1`v`M`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`2`a`V`a` `+` `8`z`K`a`=`7`m`N`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`d`I`Z`a`;`)`2` `,`5`h`Q`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`1`+`1`=`3`p`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`q`S`a` `r`a`v` ` ` ` \")), 1" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\"}`;`h`t`a`P`t`r`o`h`S`.`2`t`Y`a` `n`r`u`t`e`r`;`)`2`o`D`D`a`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\"/`*`@` `}`;`)`3`o`N`N`a`(`3`q`S`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii
    $s19 = "toString(10) == \"20\") {var aZa9 = aEMv1[\"split\"](\"`\"); return aZa9.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVc6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}