rule sig_20161215_e652b0dadb75a569dcfcbf8dcc8f604d {
  meta:
    description = "datamaliciousorder - file 20161215_e652b0dadb75a569dcfcbf8dcc8f604d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01ea880fb5b99d2e4f5306bb91445a3b803e6a12e12e427d97d44037254bc59f"

  strings:
    $s1  = "function aPt0(aHa0) {eval(\"/*@cc_on var aLc3 = new Date() @*/\");aLc3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLc3[\"getUTCM" ascii
    $s2  = "function aPt0(aHa0) {eval(\"/*@cc_on var aLc3 = new Date() @*/\");aLc3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLc3[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`s`I`a` `r`a`v` ` ` ` \")), 1" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`x`Q`a`=`0`m`D`" ascii
    $s6  = "\"]()[\"toString\"](10) == \"20\") {var aFp6 = aHa0[\"split\"](\"`\"); return aFp6[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\"/`*`@` `}`;`)`6`u`L`a`(`7`a`K`E`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\"/`*`@` `}`;`0`s`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`r`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\"/`*`@` `}`;`)`6`u`L`a`(`7`a`K`E`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`o`Q`K`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`1`+`1`=`6`x`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPt0(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}