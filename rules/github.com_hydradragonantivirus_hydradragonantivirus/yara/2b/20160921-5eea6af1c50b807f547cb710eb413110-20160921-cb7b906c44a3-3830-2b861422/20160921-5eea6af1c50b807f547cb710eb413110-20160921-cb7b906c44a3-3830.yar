rule _20160921_5eea6af1c50b807f547cb710eb413110_20160921_cb7b906c44a3_3830 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"

  strings:
    $s1 = "Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(functio" ascii
    $s2 = "urn \"GGn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"EZu\";})(),(" ascii
    $s3 = ",(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){re" ascii
    $s4 = "){return \"Oe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(" ascii
    $s5 = ",(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){r" ascii
    $s6 = " f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"W" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}