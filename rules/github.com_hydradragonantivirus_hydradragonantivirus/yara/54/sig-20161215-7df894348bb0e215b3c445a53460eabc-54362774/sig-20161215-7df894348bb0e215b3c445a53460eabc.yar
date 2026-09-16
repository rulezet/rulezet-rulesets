rule sig_20161215_7df894348bb0e215b3c445a53460eabc {
  meta:
    description = "datamaliciousorder - file 20161215_7df894348bb0e215b3c445a53460eabc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c93fd23feb2f4b5a1c17a2b7f8d8a072b46d26accb3cc21393e813e139e1b20"

  strings:
    $s1  = "function aCj6(aMv4) {eval(\"/*@cc_on var aXf6 = new Date() @*/\");aXf6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXf6[\"getUTCM" ascii
    $s2  = "function aCj6(aMv4) {eval(\"/*@cc_on var aXf6 = new Date() @*/\");aXf6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXf6[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"/`*`@` `}`;`)`0`u`X`a`(`7`y`L`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"/`*`@` `}`;`0`k`X`a` `n`r`u`t`e`r`;`}`;`)`2`z`D`S`a`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"/`*`@` `}`;`)`0`u`X`a`(`7`y`L`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"/`*`@` `}`;`4`v`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\";`0` `=` `8`y`I`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s12 = "\"]()[\"toString\"](10) == \"20\") {var aXk0 = aMv4[\"split\"](\"`\"); return aXk0[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`k`M`a`;`)`2` `,`0`m`X`B`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`i`H`R`a` `r`a`v` ` ` ` \"))," ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"/`*`@` `}`;`2`z`O`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\"/`*`@` `}`;`4`v`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`d`S`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCj6(\";`)`\\x22`8`m`l`f`l`r`3`/`u`r`.`k`r`t`m`\\x22` `+` `5`s`B`a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}