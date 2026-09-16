rule _20160921_8a4a5c81c02126f78061e6b947b8f9bc_20160921_bd6b4f506f52_5496 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"
    hash3       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"

  strings:
    $s1 = "(){return \"Cd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";" ascii
    $s2 = "IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"DAa\";})(),(functi" ascii
    $s3 = "return \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s4 = "(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck()" ascii
    $s5 = "urn \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}