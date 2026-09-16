rule _20160921_85b0b94900915170fd854268d8d17fd4_20160921_8621b60975e0_3948 {
  meta:
    description = "datamaliciousorder - from files 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash4       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"

  strings:
    $s1 = "{return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(" ascii
    $s2 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})()," ascii
    $s3 = "function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){re" ascii
    $s4 = "Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function" ascii
    $s5 = "ion f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return" ascii
    $s6 = ")(),(function f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Do\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}