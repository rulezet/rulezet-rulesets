rule sig_20161214_ebff692ef1f148a4686b70e0121c8bf9 {
  meta:
    description = "datamaliciousorder - file 20161214_ebff692ef1f148a4686b70e0121c8bf9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6aa030df6442797c43e218725226618e241fde1ce9f828b2adabdcf52880386e"

  strings:
    $s1  = "function aJAk1(aLOz7) {eval(\"/*@cc_on var aZHv6 = new Date() @*/\");aZHv6[\"setUTCSeconds\"](\"0\", \"20\");if (aZHv6.getUTCMil" ascii
    $s2  = "function aJAk1(aLOz7) {eval(\"/*@cc_on var aZHv6 = new Date() @*/\");aZHv6[\"setUTCSeconds\"](\"0\", \"20\");if (aZHv6.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`y`A`a`;`)`2` `,`6`s`U`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\"/`*`@` `}`;`5`x`E`a` `n`r`u`t`e`r`;`}`;`)`6`z`X`J`a`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\"/`*`@` `}`;`)`7`m`T`Z`a`(`7`n`B`Q`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`h`N`L`a`=`2`d" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\"/`*`@` `}`;`7`z`O`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`h`N`L`a`=`2`d" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\"/`*`@` `}`;`7`z`O`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJAk1(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}