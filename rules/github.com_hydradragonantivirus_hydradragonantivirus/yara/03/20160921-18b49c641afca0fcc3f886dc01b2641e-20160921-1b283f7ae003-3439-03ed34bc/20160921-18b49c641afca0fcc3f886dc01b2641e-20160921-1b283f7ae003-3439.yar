rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_1b283f7ae003_3439 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash3       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash4       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash5       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"

  strings:
    $s1 = "n f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s2 = "ion f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s3 = "){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(" ascii
    $s4 = "z\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s5 = "f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn" ascii
    $s6 = " \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}