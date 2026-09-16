rule sig_20161215_bca9f6a493ce7aa26cfd781196230b8e {
  meta:
    description = "datamaliciousorder - file 20161215_bca9f6a493ce7aa26cfd781196230b8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bf71ef2c369a4a2b6fa907022c9abc63174fcd91ff4e708403c08b6e5492432"

  strings:
    $s1  = "function aQy8(aSSt4) {eval(\"/*@cc_on var aOZx1 = new Date() @*/\");aOZx1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aOZx1[\"get" ascii
    $s2  = "function aQy8(aSSt4) {eval(\"/*@cc_on var aOZx1 = new Date() @*/\");aOZx1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aOZx1[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\"/`*`@` `}`;`)`5`c`W`P`a`(`6`q`B`F`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`h`G`E`a`=`5`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\"/`*`@` `}`;`4`t`S`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`1`+`1`=`1`t`J`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\"/`*`@` `}`;`0`w`X`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`1`+`1`=`1`t`J`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\"/`*`@` `}`;`)`5`c`W`P`a`(`6`q`B`F`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`j`I`a`;`)`2` `,`4`z`U`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`)`\\x22`m`f`a`6`0`v`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`t`n`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`)`\\x22`d`w`n`h`3`c`m`/`m`o`c`.`i`a`i`d`u`w`\\x22` `+` `2`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\"}`;`h`t`a`P`t`r`o`h`S`.`3`g`B`a` `n`r`u`t`e`r`;`)`5`v`B`a`(`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`j`I`a`;`)`2` `,`4`z`U`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\"/`*`@` `}`;`4`t`S`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQy8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}