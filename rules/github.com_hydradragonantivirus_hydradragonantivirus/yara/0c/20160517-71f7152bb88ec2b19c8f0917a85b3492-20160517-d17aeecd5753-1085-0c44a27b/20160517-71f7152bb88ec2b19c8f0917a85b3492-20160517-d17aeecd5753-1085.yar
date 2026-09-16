rule _20160517_71f7152bb88ec2b19c8f0917a85b3492_20160517_d17aeecd5753_1085 {
  meta:
    description = "datamaliciousorder - from files 20160517_71f7152bb88ec2b19c8f0917a85b3492.js, 20160517_d17aeecd5753a6ba81e46eec5a628cc6.js, 20160517_fdb0f5a3fd8e13a24553b767e7bdd1e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "383b9cc3334c94f88e96630fd0b077c2ad30249c2a4b32b336a5cc6905bb80c9"
    hash2       = "c260b68751ce575d346c1852a382aef4049765c8ee5bef391364f7b92339de48"
    hash3       = "1c8afee04ba45fc1aaa9e41a30a3e71f356fcdfb7682c180fb4edd588e26bb37"

  strings:
    $s1 = "var nConverts1 /* K  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* K  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* K  */;};" fullword ascii
    $s4 = "enjoy1 /* K  */ /* K  */= true;/* K  */" fullword ascii
    $s5 = "batch =/* K  */ \"R\" + \"esponseB\"/* K  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "could = /* K  */(/* K  */\"noitisop\").split(''/* K  */).reverse(/* K  */).join('');" fullword ascii
    $s7 = "var enjoy1 /* K  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}