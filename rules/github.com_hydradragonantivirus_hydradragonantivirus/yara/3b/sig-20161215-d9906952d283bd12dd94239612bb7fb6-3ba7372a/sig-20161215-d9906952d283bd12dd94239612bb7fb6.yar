rule sig_20161215_d9906952d283bd12dd94239612bb7fb6 {
  meta:
    description = "datamaliciousorder - file 20161215_d9906952d283bd12dd94239612bb7fb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f628eb9c07cb8c9d71a9cb1ca1a8d30b1f4744d9742baa8cac57965eee2146a"

  strings:
    $s1  = "function aBk3(aCYq7) {eval(\"/*@cc_on var aAv9 = new Date() @*/\");aAv9[\"setUTCSeconds\"](\"0\", \"20\");if (aAv9.getUTCMillise" ascii
    $s2  = "function aBk3(aCYq7) {eval(\"/*@cc_on var aAv9 = new Date() @*/\");aAv9[\"setUTCSeconds\"](\"0\", \"20\");if (aAv9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\"/`*`@` `}`;`)`4`s`N`a`(`0`b`A`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s4  = "toString(10) == \"20\") {var aYTt7 = aCYq7[\"split\"](\"`\"); return aYTt7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`m`W`a`;`)`2` `,`4`a`T`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\"/`*`@` `}`;`7`t`T`Y`a` `n`r`u`t`e`r`;`}`;`)`6`i`T`a`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`v`F`Z`a` `n`r`u`t`e`r`;`)`6`p`Q`a`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`v`F`Z`a` `n`r`u`t`e`r`;`)`6`p`Q`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`s`X`a` `r`a`v` ` ` ` \")), 1" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`m`W`a`;`)`2` `,`4`a`T`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`5`k`Y`a` `+` `1`l`F`a`=`6`z`U`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBk3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`z`U`a`=`6`p`Q`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}