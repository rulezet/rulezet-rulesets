rule sig_20161214_03fb0b46151a90fb144e416d5647f5b3 {
  meta:
    description = "datamaliciousorder - file 20161214_03fb0b46151a90fb144e416d5647f5b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee74c646f34dfed309f14b594a4be8253bf18cb9123903a8c15ee83d79c7a693"

  strings:
    $s1  = "function aMEf9(aDk4) {eval(\"/*@cc_on var aHt6 = new Date() @*/\");aHt6[\"setUTCSeconds\"](\"0\", \"20\");if (aHt6.getUTCMillise" ascii
    $s2  = "function aMEf9(aDk4) {eval(\"/*@cc_on var aHt6 = new Date() @*/\");aHt6[\"setUTCSeconds\"](\"0\", \"20\");if (aHt6.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\"}`;`h`t`a`P`t`r`o`h`S`.`1`e`Y`L`a` `n`r`u`t`e`r`;`)`0`g`W`a" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "toString(10) == \"20\") {var aXJi2 = aDk4[\"split\"](\"`\"); return aXJi2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`1`+`1`=`3`b`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`0` `=` `7`s`D`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `7`v`J`R`a`(" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\"/`*`@` `}`;`9`h`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`m`N`a` `r`a`v` ` ` ` \")), " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`0`y`X`a` `+` `9`s`O`A`a`=`0`f`E`C`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`f`E`C`a`=`0`g" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMEf9(\";`1`+`1`=`3`b`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}