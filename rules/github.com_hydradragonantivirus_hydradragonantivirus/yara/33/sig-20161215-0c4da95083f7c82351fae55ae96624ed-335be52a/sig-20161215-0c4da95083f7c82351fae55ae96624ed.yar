rule sig_20161215_0c4da95083f7c82351fae55ae96624ed {
  meta:
    description = "datamaliciousorder - file 20161215_0c4da95083f7c82351fae55ae96624ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e9aea23bdf865e8dde7193e13d50f6d6f3362fda16f6b792a8ef13b055d844b"

  strings:
    $s1  = "function aBp5(aJe4) {eval(\"/*@cc_on var aJl2 = new Date() @*/\");aJl2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJl2[\"getUTCM" ascii
    $s2  = "function aBp5(aJe4) {eval(\"/*@cc_on var aJl2 = new Date() @*/\");aJl2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJl2[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\"/`*`@` `}`;`)`9`z`K`H`a`(`1`j`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\"/`*`@` `}`;`)`9`z`K`H`a`(`1`j`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`4`x`K`O`a` `+` `6`k`L`a`=`2`e`S`V`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`f`H`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`)`\\x22`a`i`v`p`e`c`0`/`e`d`.`a`v`i`d`-`s`l`e`g`n`a`-`n`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`f`H`a` `r`a`v` `;`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\"}`;`h`t`a`P`t`r`o`h`S`.`7`r`G`S`a` `n`r`u`t`e`r`;`)`5`c`C`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\"/`*`@` `}`;`8`g`P`a` `n`r`u`t`e`r`;`}`;`)`8`v`Y`a`(`]`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`1`+`1`=`2`p`P`R`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\"\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\"/`*`@` `}`;`8`g`P`a` `n`r`u`t`e`r`;`}`;`)`8`v`Y`a`(`]`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\"/`*`@` `}`;`4`e`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s19 = "\"]()[\"toString\"](10) == \"20\") {var aPg8 = aJe4[\"split\"](\"`\"); return aPg8[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBp5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}