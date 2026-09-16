rule sig_20161215_9c1fd93f40cfb6cdb23acf09a28ef043 {
  meta:
    description = "datamaliciousorder - file 20161215_9c1fd93f40cfb6cdb23acf09a28ef043.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a57d2515a6de7c56ab88cb45496c03b8892d4affffd8e7cff7ff1f8e9b91ef08"

  strings:
    $s1  = "function aOg6(aQb5) {eval(\"/*@cc_on var aLDv9 = new Date() @*/\");aLDv9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLDv9[\"getU" ascii
    $s2  = "function aOg6(aQb5) {eval(\"/*@cc_on var aLDv9 = new Date() @*/\");aLDv9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLDv9[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`v`w`h`2`8`/`m`o`c`.`g`f`s`u`m`a`n`i`d`\\x22` `+` `" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`1`+`1`=`3`u`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`v`w`h`2`8`/`m`o`c`.`g`f`s`u`m`a`n`i`d`\\x22` `+` `" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` `" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`0` `=` `5`q`V`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\"}`;`h`t`a`P`t`r`o`h`S`.`3`z`W`a` `n`r`u`t`e`r`;`)`8`x`G`Q`a`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\"/`*`@` `}`;`)`6`p`Z`a`(`2`o`S`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\"/`*`@` `}`;`6`s`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`m`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\"/`*`@` `}`;`)`6`p`Z`a`(`2`o`S`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii
    $s18 = "nds\"]()[\"toString\"](10) == \"20\") {var aGEm2 = aQb5[\"split\"](\"`\"); return aGEm2[\"reverse\"]().join(\"\");} else return " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\"/`*`@` `}`;`5`b`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOg6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`w`Z`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}