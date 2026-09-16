rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_6d45b48d2143_3307 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"

  strings:
    $s1 = "turn \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s2 = "\"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s3 = "(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})" ascii
    $s4 = "turn \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5 = "00(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc" ascii
    $s6 = "turn \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}