rule sig_20161215_a2229a0b45bf9f04a7221a887124d108 {
  meta:
    description = "datamaliciousorder - file 20161215_a2229a0b45bf9f04a7221a887124d108.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f04485b90b5938035d2261ad7577bb268dbd245a45be7690f8416015ad75e817"

  strings:
    $s1  = "function aWr0(aRh4) {eval(\"/*@cc_on var aVIy7 = new Date() @*/\");aVIy7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVIy7[\"getU" ascii
    $s2  = "function aWr0(aRh4) {eval(\"/*@cc_on var aVIy7 = new Date() @*/\");aVIy7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVIy7[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`u`X`a`;`)`2` `,`4`r`Y`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`0` `=` `0`o`R`E`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`u`T`Q`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\"/`*`@` `}`;`7`h`O`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\"/`*`@` `}`;`)`0`r`E`a`(`1`u`I`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`e`G`a`=`6`n`Z`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`u`T`Q`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\"/`*`@` `}`;`3`k`M`O`a` `n`r`u`t`e`r`;`}`;`)`5`q`O`Y`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\"}`;`h`t`a`P`t`r`o`h`S`.`0`d`Z`a` `n`r`u`t`e`r`;`)`6`n`Z`H`a`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\"/`*`@` `}`;`7`h`O`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWr0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}