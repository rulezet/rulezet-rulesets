rule sig_20161215_1f4f1e3d3f62768529b25949a0f030ca {
  meta:
    description = "datamaliciousorder - file 20161215_1f4f1e3d3f62768529b25949a0f030ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b407a07ea686f45564481f33df47a77ffb8cd68d8dd89028a2c69377213db76b"

  strings:
    $s1  = "function aEn2(aWXm1) {eval(\"/*@cc_on var aKYy4 = new Date() @*/\");aKYy4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKYy4[\"get" ascii
    $s2  = "function aEn2(aWXm1) {eval(\"/*@cc_on var aKYy4 = new Date() @*/\");aKYy4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKYy4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\"/`*`@` `}`;`1`m`X`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\"/`*`@` `}`;`3`g`A`a` `n`r`u`t`e`r`;`}`;`)`5`r`P`A`a`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`t`W`G`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`3`g`Q`S`a` `+` `4`i`W`M`a`=`8`i`L`H`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`n`J`M`a`;`)`2` `,`5`z`C`X`a`(`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`1`+`1`=`8`g`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\"/`*`@` `}`;`1`m`X`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`i`L`H`a`=`2`s`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`1`+`1`=`8`g`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\"/`*`@` `}`;`8`l`A`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEn2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}