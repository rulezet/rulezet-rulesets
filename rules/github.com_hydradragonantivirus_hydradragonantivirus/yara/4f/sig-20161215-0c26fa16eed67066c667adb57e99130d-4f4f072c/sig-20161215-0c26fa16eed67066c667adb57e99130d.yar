rule sig_20161215_0c26fa16eed67066c667adb57e99130d {
  meta:
    description = "datamaliciousorder - file 20161215_0c26fa16eed67066c667adb57e99130d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e285da8e401c2253c8588cd101b3c166ce5e904edea38abca2b128483331f0a7"

  strings:
    $s1  = "function aYZg4(aAw1) {eval(\"/*@cc_on var aXEi0 = new Date() @*/\");aXEi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXEi0[\"get" ascii
    $s2  = "function aYZg4(aAw1) {eval(\"/*@cc_on var aXEi0 = new Date() @*/\");aXEi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aXEi0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"/`*`@` `}`;`2`p`B`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"/`*`@` `}`;`5`n`J`Y`a` `n`r`u`t`e`r`;`}`;`)`1`t`K`a`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`1`+`1`=`3`j`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"/`*`@` `}`;`5`n`J`Y`a` `n`r`u`t`e`r`;`}`;`)`1`t`K`a`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `5`c" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"/`*`@` `}`;`)`7`l`L`W`a`(`8`q`Q`W`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"}`;`h`t`a`P`t`r`o`h`S`.`8`h`Q`K`a` `n`r`u`t`e`r`;`)`3`l`Q`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"/`*`@` `}`;`)`7`l`L`W`a`(`8`q`Q`W`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`k`J`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\"/`*`@` `}`;`1`w`A`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYZg4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`k`J`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}