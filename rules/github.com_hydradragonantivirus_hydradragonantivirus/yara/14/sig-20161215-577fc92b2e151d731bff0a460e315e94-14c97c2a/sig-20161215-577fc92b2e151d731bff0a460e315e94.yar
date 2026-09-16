rule sig_20161215_577fc92b2e151d731bff0a460e315e94 {
  meta:
    description = "datamaliciousorder - file 20161215_577fc92b2e151d731bff0a460e315e94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bb673f591627d6a520a3fe4737a0b20ba32e5feb53de84d4cf4e6cdbb9ee558"

  strings:
    $s1  = "function aCQx6(aRUw5) {eval(\"/*@cc_on var aGw5 = new Date() @*/\");aGw5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGw5[\"getUT" ascii
    $s2  = "function aCQx6(aRUw5) {eval(\"/*@cc_on var aGw5 = new Date() @*/\");aGw5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGw5[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`)`\\x22`0`x`i`1`u`m`j`/`u`r`.`u`g`n`e`l`f`e`\\x22` `+` `1" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\"/`*`@` `}`;`3`s`E`A`a` `n`r`u`t`e`r`;`}`;`)`2`k`X`a`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\"/`*`@` `}`;`9`y`K`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`1`+`1`=`3`x`D`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\"}`;`h`t`a`P`t`r`o`h`S`.`0`v`N`B`a` `n`r`u`t`e`r`;`)`1`b`U`a" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`1`+`1`=`3`x`D`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\"/`*`@` `}`;`)`7`x`U`a`(`3`i`N`W`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\"/`*`@` `}`;`3`s`E`A`a` `n`r`u`t`e`r`;`}`;`)`2`k`X`a`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`m`D`R`a` `r`a`v` `;" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`0` `=` `8`q`W`J`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\"/`*`@` `}`;`9`y`K`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCQx6(\"}`;`h`t`a`P`t`r`o`h`S`.`0`v`N`B`a` `n`r`u`t`e`r`;`)`1`b`U`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}