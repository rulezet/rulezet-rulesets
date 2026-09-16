rule sig_20161214_a8d72cf3b71ad4385ae1733c0a9cda86 {
  meta:
    description = "datamaliciousorder - file 20161214_a8d72cf3b71ad4385ae1733c0a9cda86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d419b7c8402259d4dd2b4396cbe53693872b6a03a42f98e583a4b207bf391c06"

  strings:
    $s1  = "function aBDe2(aWd6) {eval(\"/*@cc_on var aHLv4 = new Date() @*/\");aHLv4[\"setUTCSeconds\"](\"0\", \"20\");if (aHLv4.getUTCMill" ascii
    $s2  = "function aBDe2(aWd6) {eval(\"/*@cc_on var aHLv4 = new Date() @*/\");aHLv4[\"setUTCSeconds\"](\"0\", \"20\");if (aHLv4.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\"/`*`@` `}`;`3`d`F`S`a` `n`r`u`t`e`r`;`}`;`)`0`s`K`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\"\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`1`+`1`=`9`a`I`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\"/`*`@` `}`;`6`q`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`g" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\"/`*`@` `}`;`)`8`o`K`a`(`4`p`O`R`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\"/`*`@` `}`;`6`q`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`g" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`1`+`1`=`9`a`I`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`l`Z`F`a`;`)`2` `,`6`s`Q`a`(`]" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\"/`*`@` `}`;`6`d`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\"}`;`h`t`a`P`t`r`o`h`S`.`9`i`Y`a` `n`r`u`t`e`r`;`)`6`i`A`G`a" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDe2(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}