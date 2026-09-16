rule sig_20161214_3f73e2ba08978e415dc19c1c6140a06f {
  meta:
    description = "datamaliciousorder - file 20161214_3f73e2ba08978e415dc19c1c6140a06f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c621886cbdc7514501f7e8faf4872c8380eee065d9035796300486d14fb625c2"

  strings:
    $s1  = "function aBk4(aOn9) {eval(\"/*@cc_on var aFFm5 = new Date() @*/\");aFFm5[\"setUTCSeconds\"](\"0\", \"20\");if (aFFm5.getUTCMilli" ascii
    $s2  = "function aBk4(aOn9) {eval(\"/*@cc_on var aFFm5 = new Date() @*/\");aFFm5[\"setUTCSeconds\"](\"0\", \"20\");if (aFFm5.getUTCMilli" ascii
    $s3  = ").toString(10) == \"20\") {var aQz9 = aOn9[\"split\"](\"`\"); return aQz9.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\"/`*`@` `}`;`1`a`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`r`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`f`P`W`a`=`4`b`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`3`f`X`a` `+` `2`n`B`A`a`=`4`f`P`W`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\"/`*`@` `}`;`9`n`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` `" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\"}`;`h`t`a`P`t`r`o`h`S`.`6`a`Z`a` `n`r`u`t`e`r`;`)`4`b`Z`X`a`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk4(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}