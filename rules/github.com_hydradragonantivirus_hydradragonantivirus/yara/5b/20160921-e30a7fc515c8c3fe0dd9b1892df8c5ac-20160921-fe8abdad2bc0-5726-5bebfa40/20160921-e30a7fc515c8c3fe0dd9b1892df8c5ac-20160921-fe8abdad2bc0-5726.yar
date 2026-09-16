rule _20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac_20160921_fe8abdad2bc0_5726 {
  meta:
    description = "datamaliciousorder - from files 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash2       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = "tion f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(),(function f000(){return " ascii
    $s2 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s3 = "turn \"RLk\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";})()," ascii
    $s4 = "urn \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5 = "return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"BMj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}