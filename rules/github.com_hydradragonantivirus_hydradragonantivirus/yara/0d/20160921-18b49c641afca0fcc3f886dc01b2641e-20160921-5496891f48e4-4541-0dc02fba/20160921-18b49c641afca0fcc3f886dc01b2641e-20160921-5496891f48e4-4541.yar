rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_5496891f48e4_4541 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash3       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash4       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash5       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash6       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash7       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){ret" ascii
    $s2 = "OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(funct" ascii
    $s3 = "(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){r" ascii
    $s4 = "f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"R" ascii
    $s5 = "\"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}