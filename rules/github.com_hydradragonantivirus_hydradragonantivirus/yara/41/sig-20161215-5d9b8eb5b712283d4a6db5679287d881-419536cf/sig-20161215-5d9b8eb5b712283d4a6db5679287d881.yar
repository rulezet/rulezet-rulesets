rule sig_20161215_5d9b8eb5b712283d4a6db5679287d881 {
  meta:
    description = "datamaliciousorder - file 20161215_5d9b8eb5b712283d4a6db5679287d881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "277287ece888566ea5fde596c1fa806424ef0155e20dc99a0619e7a6ca41bb87"

  strings:
    $s1  = "function aQEd2(aWIp9) {eval(\"/*@cc_on var aAb3 = new Date() @*/\");aAb3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAb3[\"getUT" ascii
    $s2  = "function aQEd2(aWIp9) {eval(\"/*@cc_on var aAb3 = new Date() @*/\");aAb3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAb3[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`1`+`1`=`0`o`L`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\"\")), 1);" fullword ascii
    $s7  = "ds\"]()[\"toString\"](10) == \"20\") {var aGm5 = aWIp9[\"split\"](\"`\"); return aGm5[\"reverse\"]().join(\"\");} else return \"" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`c`T`a`;`)`2` `,`7`l`B`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\"/`*`@` `}`;`5`m`G`a` `n`r`u`t`e`r`;`}`;`)`6`f`X`a`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\"/`*`@` `}`;`)`1`w`C`a`(`3`h`E`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\"}`;`h`t`a`P`t`r`o`h`S`.`0`j`P`a` `n`r`u`t`e`r`;`)`5`l`D`J`a" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`0` `=` `8`l`H`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`c`T`a`;`)`2` `,`7`l`B`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQEd2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`a`Z`a` `r`a`v` ` ` ` \")), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}