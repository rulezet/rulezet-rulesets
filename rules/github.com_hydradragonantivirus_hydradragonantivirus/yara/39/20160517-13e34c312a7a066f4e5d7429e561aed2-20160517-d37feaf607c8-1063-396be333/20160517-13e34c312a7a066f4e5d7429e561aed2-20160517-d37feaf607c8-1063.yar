rule _20160517_13e34c312a7a066f4e5d7429e561aed2_20160517_d37feaf607c8_1063 {
  meta:
    description = "datamaliciousorder - from files 20160517_13e34c312a7a066f4e5d7429e561aed2.js, 20160517_d37feaf607c83b38d9e82401877f33b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b25946a496358f1261b25b40afa33f8c5e6a5e311cd128034c00a8ffdc871f57"
    hash2       = "02e37c9b05519ee33aee0dc8eae6a67e5461ced317412674ae53033977b4412c"

  strings:
    $s1 = "var nConverts1 /* u  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* u  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* u  */;};" fullword ascii
    $s4 = "could = /* u  */(/* u  */\"noitisop\").split(''/* u  */).reverse(/* u  */).join('');" fullword ascii
    $s5 = "var enjoy1 /* u  */ = false;" fullword ascii
    $s6 = "enjoy1 /* u  */ /* u  */= true;/* u  */" fullword ascii
    $s7 = "batch =/* u  */ \"R\" + \"esponseB\"/* u  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}