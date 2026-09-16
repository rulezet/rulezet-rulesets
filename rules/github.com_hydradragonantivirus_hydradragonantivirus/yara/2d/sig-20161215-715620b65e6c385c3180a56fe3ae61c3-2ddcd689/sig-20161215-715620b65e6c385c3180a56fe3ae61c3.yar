rule sig_20161215_715620b65e6c385c3180a56fe3ae61c3 {
  meta:
    description = "datamaliciousorder - file 20161215_715620b65e6c385c3180a56fe3ae61c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0e9a0f2aa3f4580ea27547d54af04f3af8e1743eefbc468651613a857f18798"

  strings:
    $s1  = "function aYc8(aQt0) {eval(\"/*@cc_on var aUWb7 = new Date() @*/\");aUWb7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUWb7[\"getU" ascii
    $s2  = "function aYc8(aQt0) {eval(\"/*@cc_on var aUWb7 = new Date() @*/\");aUWb7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUWb7[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`1`+`1`=`8`d`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`q`H`K`a`=`1`w`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s8  = "nds\"]()[\"toString\"](10) == \"20\") {var aAJn9 = aQt0[\"split\"](\"`\"); return aAJn9[\"reverse\"]().join(\"\");} else return " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`0`r`Z`a` `+` `7`t`R`a`=`4`q`H`K`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`y`B`M`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`e`U`a` `r`a`v` ` ` ` \")), 1" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\"/`*`@` `}`;`6`g`F`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\"/`*`@` `}`;`9`n`J`A`a` `n`r`u`t`e`r`;`}`;`)`4`j`F`O`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`a`K`X`a`;`)`2` `,`4`r`M`C`a`(`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYc8(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}