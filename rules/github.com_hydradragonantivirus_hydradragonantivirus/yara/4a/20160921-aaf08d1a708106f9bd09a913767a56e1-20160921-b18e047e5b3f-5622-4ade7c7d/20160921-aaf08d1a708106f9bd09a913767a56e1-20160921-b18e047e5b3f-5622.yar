rule _20160921_aaf08d1a708106f9bd09a913767a56e1_20160921_b18e047e5b3f_5622 {
  meta:
    description = "datamaliciousorder - from files 20160921_aaf08d1a708106f9bd09a913767a56e1.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"
    hash2       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash3       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash4       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1 = "urn \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s2 = "(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(" ascii
    $s3 = " \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(funct" ascii
    $s4 = ")(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000" ascii
    $s5 = " f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}