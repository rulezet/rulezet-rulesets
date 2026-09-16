rule sig_20161214_f63c758a743412d5be8612e1579b224c {
  meta:
    description = "datamaliciousorder - file 20161214_f63c758a743412d5be8612e1579b224c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "494a12cee54ec310947676ccfe1693c873c3e7545d6e343a3025036ec76043f1"

  strings:
    $s1  = "function aWIy7(aSz8) {eval(\"/*@cc_on var aXLp6 = new Date() @*/\");aXLp6[\"setUTCSeconds\"](\"0\", \"20\");if (aXLp6.getUTCMill" ascii
    $s2  = "function aWIy7(aSz8) {eval(\"/*@cc_on var aXLp6 = new Date() @*/\");aXLp6[\"setUTCSeconds\"](\"0\", \"20\");if (aXLp6.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`1`+`1`=`6`w`I`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\"/`*`@` `}`;`)`9`v`Y`a`(`3`g`M`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\"/`*`@` `}`;`0`y`E`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\"/`*`@` `}`;`0`y`E`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\"/`*`@` `}`;`8`z`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`x`Q`Q`a`=`6`g" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\"/`*`@` `}`;`9`t`Z`a` `n`r`u`t`e`r`;`}`;`)`5`z`V`a`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\"}`;`h`t`a`P`t`r`o`h`S`.`9`q`A`Z`a` `n`r`u`t`e`r`;`)`6`g`A`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\"}`;`h`t`a`P`t`r`o`h`S`.`9`q`A`Z`a` `n`r`u`t`e`r`;`)`6`g`A`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`0` `=` `2`g`V`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`7`q`G`E`a` `+` `9`z`I`I`a`=`8`x`Q`Q`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\"/`*`@` `}`;`8`z`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`w`A`a` `r`a`v` ` ` ` \")), " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWIy7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "().toString(10) == \"20\") {var aZt9 = aSz8[\"split\"](\"`\"); return aZt9.reverse().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}