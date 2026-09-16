rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_b32c8921e339_4641 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_cbfbdc544b309301bc71d300d7726545.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash3       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"

  strings:
    $s1 = "0(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";" ascii
    $s2 = "q\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function " ascii
    $s3 = ",(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){" ascii
    $s4 = "return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})()," ascii
    $s5 = "n f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"W" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}