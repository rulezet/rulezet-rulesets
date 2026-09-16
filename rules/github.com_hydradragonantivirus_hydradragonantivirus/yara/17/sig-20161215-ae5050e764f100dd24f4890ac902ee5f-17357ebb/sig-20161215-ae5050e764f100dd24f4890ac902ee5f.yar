rule sig_20161215_ae5050e764f100dd24f4890ac902ee5f {
  meta:
    description = "datamaliciousorder - file 20161215_ae5050e764f100dd24f4890ac902ee5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462652b1a8158d4a42f3020613b0cf941bd5738723cc5940f50ad1f30025fef1"

  strings:
    $s1  = "function aFLq4(aCMd1) {eval(\"/*@cc_on var aJLw0 = new Date() @*/\");aJLw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJLw0[\"ge" ascii
    $s2  = "function aFLq4(aCMd1) {eval(\"/*@cc_on var aJLw0 = new Date() @*/\");aJLw0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJLw0[\"ge" ascii
    $s3  = "conds\"]()[\"toString\"](10) == \"20\") {var aTk0 = aCMd1[\"split\"](\"`\"); return aTk0[\"reverse\"]().join(\"\");} else return" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`2`j`N`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`)`8`c`O`N`a`(`5`n`Y`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`2`j`N`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`1`d`M`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`0`k`T`a` `n`r`u`t`e`r`;`}`;`)`0`z`P`P`a`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`0`k`T`a` `n`r`u`t`e`r`;`}`;`)`0`z`P`P`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`t`C`D`a`=`7`n" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`s`E`a` `r`a`v` `;`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`)`8`c`O`N`a`(`5`n`Y`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFLq4(\"/`*`@` `}`;`1`d`M`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}