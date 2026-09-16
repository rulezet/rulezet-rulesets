rule sig_20161215_c3be43fa75cdd25821b302510a714cfc {
  meta:
    description = "datamaliciousorder - file 20161215_c3be43fa75cdd25821b302510a714cfc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c292476f6e8c5a33fa837eb0fb3281012126badfea43b07cd3cca39829f9844"

  strings:
    $s1  = "function aRVc1(aHk8) {eval(\"/*@cc_on var aKXz8 = new Date() @*/\");aKXz8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKXz8[\"get" ascii
    $s2  = "function aRVc1(aHk8) {eval(\"/*@cc_on var aKXz8 = new Date() @*/\");aKXz8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKXz8[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\"}`;`h`t`a`P`t`r`o`h`S`.`5`d`Q`Z`a` `n`r`u`t`e`r`;`)`3`l`E`T" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\"/`*`@` `}`;`8`k`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`)`\\x22`y`b`c`h`j`/`m`o`c`.`c`n`i`l`o`s`h`c`e`t`i`h`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`o`R`a`=`3`l`E" ascii
    $s8  = "onds\"]()[\"toString\"](10) == \"20\") {var aPv6 = aHk8[\"split\"](\"`\"); return aPv6[\"reverse\"]().join(\"\");} else return " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\"/`*`@` `}`;`2`x`T`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`p`G`a`;`)`2` `,`0`o`A`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\"/`*`@` `}`;`6`v`P`a` `n`r`u`t`e`r`;`}`;`)`7`n`R`N`a`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRVc1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`n`X`W`a` `r`a`v` `;" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}