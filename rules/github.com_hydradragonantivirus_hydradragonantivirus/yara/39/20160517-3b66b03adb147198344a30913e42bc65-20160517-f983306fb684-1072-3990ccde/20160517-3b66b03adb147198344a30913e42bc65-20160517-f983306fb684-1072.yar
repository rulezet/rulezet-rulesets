rule _20160517_3b66b03adb147198344a30913e42bc65_20160517_f983306fb684_1072 {
  meta:
    description = "datamaliciousorder - from files 20160517_3b66b03adb147198344a30913e42bc65.js, 20160517_f983306fb684590bbc256cadd57e34be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "263d57669a3c104809d3eb2e537efaedacde7f4e4513c6ee1d4c1fc010628220"
    hash2       = "eab8a8cabf38b9198708cf79c859829a347f3812783384c1e6f913fc1753997a"

  strings:
    $s1 = "var nConverts1 /* I  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* I  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* I  */;};" fullword ascii
    $s4 = "enjoy1 /* I  */ /* I  */= true;/* I  */" fullword ascii
    $s5 = "batch =/* I  */ \"R\" + \"esponseB\"/* I  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "could = /* I  */(/* I  */\"noitisop\").split(''/* I  */).reverse(/* I  */).join('');" fullword ascii
    $s7 = "var enjoy1 /* I  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}