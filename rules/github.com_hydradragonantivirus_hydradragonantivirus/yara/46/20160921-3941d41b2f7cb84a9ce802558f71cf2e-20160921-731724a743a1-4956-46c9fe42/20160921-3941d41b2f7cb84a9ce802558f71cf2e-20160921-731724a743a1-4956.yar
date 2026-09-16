rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_731724a743a1_4956 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_86f41d8c83240a68770674107f15f162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash3       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"

  strings:
    $s1 = "{return \"DNa\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s2 = "turn \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})()," ascii
    $s3 = "ction f000(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s4 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f" ascii
    $s5 = "ion f000(){return \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}