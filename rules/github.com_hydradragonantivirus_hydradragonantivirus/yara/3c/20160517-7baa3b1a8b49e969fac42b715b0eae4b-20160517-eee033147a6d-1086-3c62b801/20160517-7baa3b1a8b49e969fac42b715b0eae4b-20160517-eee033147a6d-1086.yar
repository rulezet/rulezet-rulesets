rule _20160517_7baa3b1a8b49e969fac42b715b0eae4b_20160517_eee033147a6d_1086 {
  meta:
    description = "datamaliciousorder - from files 20160517_7baa3b1a8b49e969fac42b715b0eae4b.js, 20160517_eee033147a6d8e4b103db54efb49463f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2168595504b4e1315a31b18ac13f71a43c35ae720d20ae7846f57a8ffe5a9df"
    hash2       = "3b17e980b3df9dc766bc20eeacb4c9bf9c7d3031e293a6f183f51a41a74133af"

  strings:
    $s1 = "var nConverts1 /* A  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* A  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* A  */;};" fullword ascii
    $s4 = "var enjoy1 /* A  */ = false;" fullword ascii
    $s5 = "batch =/* A  */ \"R\" + \"esponseB\"/* A  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "could = /* A  */(/* A  */\"noitisop\").split(''/* A  */).reverse(/* A  */).join('');" fullword ascii
    $s7 = "enjoy1 /* A  */ /* A  */= true;/* A  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}