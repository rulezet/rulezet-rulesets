rule sig_20161215_71486af40c02bad2498a118dd5a3637a {
  meta:
    description = "datamaliciousorder - file 20161215_71486af40c02bad2498a118dd5a3637a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75fc3518b64f4197444f2eb3c6524e518e352c92462ba8d5042c9a3e8806b317"

  strings:
    $s1  = "function aFh9(aPi3) {eval(\"/*@cc_on var aAl1 = new Date() @*/\");aAl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAl1[\"getUTCM" ascii
    $s2  = "function aFh9(aPi3) {eval(\"/*@cc_on var aAl1 = new Date() @*/\");aAl1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAl1[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `5`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\"/`*`@` `}`;`3`l`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`m`Z`J`a` `r`a`v` ` ` ` \"))," ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\"/`*`@` `}`;`3`l`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`0` `=` `4`i`T`Y`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`j`Y`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`c`R`X`a`=`6`h`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\"/`*`@` `}`;`6`a`N`H`a` `n`r`u`t`e`r`;`}`;`)`5`m`L`M`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`u`U`Z`a`(`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\"}`;`h`t`a`P`t`r`o`h`S`.`2`t`T`P`a` `n`r`u`t`e`r`;`)`6`h`J`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFh9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`c`R`X`a`=`6`h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}