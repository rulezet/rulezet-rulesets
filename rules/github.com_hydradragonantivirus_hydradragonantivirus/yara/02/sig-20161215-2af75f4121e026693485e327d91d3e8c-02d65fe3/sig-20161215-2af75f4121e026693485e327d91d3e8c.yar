rule sig_20161215_2af75f4121e026693485e327d91d3e8c {
  meta:
    description = "datamaliciousorder - file 20161215_2af75f4121e026693485e327d91d3e8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f1571d039999db11d6669b432dc702b3ea87c815fd04ab6b7658f5defcb6b10"

  strings:
    $s1  = "function aFm0(aLDf8) {eval(\"/*@cc_on var aWYm6 = new Date() @*/\");aWYm6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWYm6[\"get" ascii
    $s2  = "function aFm0(aLDf8) {eval(\"/*@cc_on var aWYm6 = new Date() @*/\");aWYm6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWYm6[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`l`E`a`;`)`2` `,`0`i`F`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`2`y`C`L`a` `+` `0`j`K`U`a`=`7`t`T`B`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`1`+`1`=`1`y`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\"/`*`@` `}`;`5`y`F`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\"}`;`h`t`a`P`t`r`o`h`S`.`7`v`Y`a` `n`r`u`t`e`r`;`)`6`u`E`a`(`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`h`W`P`a` `r`a`v` ` ` ` \"))," ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\"/`*`@` `}`;`5`y`F`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\"/`*`@` `}`;`8`f`D`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`1`+`1`=`1`y`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` `" ascii
    $s17 = "onds\"]()[\"toString\"](10) == \"20\") {var aAp5 = aLDf8[\"split\"](\"`\"); return aAp5[\"reverse\"]().join(\"\");} else return " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFm0(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}